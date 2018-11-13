package inkfish

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	tags "github.com/aws/aws-sdk-go/service/resourcegroupstaggingapi"
	"github.com/pkg/errors"
	"log"
	"strings"
)

var arnToIP = map[string]string{}

func UpdateMetadataFromAWS(sess *session.Session, cache *MetadataCache) {
	ipToTag, err := MakeIPToTagMap(sess,"ProxyUser")
	if err != nil {
		log.Println("failed to read aws metadata: ", err)
	} else {
		cache.Replace(ipToTag)
	}
}

func MakeIPToTagMap(sess *session.Session, targetTag string) (map[string]string, error) {
	arnToTag, err := getInstanceTagValues(sess, targetTag)
	if err != nil {
		return nil, errors.Wrap(err, "getting instance tag values")
	}
	ipToTag := map[string]string{}
	for instanceId, instanceTagValue := range arnToTag {
		// Pull instance IP into cache if we don't have it
		if _, ok := arnToIP[instanceId]; !ok {
			primaryIP, err := getInstancePrimaryIP(sess, instanceId)
			if err != nil {
				return nil, errors.Wrap(err, "getting instance primary ip")
			} else {
				arnToIP[instanceId] = primaryIP
			}
		}
		// Update our metadata map
		if instanceIP, ok := arnToIP[instanceId]; ok {
			log.Printf("Found new metadata tag for IP: %v: %v\n", instanceIP, instanceTagValue)
			ipToTag[instanceIP] = instanceTagValue
		}
	}
	return ipToTag, nil
}

func getInstanceTagValues(sess *session.Session, targetTag string) (map[string]string, error) {
	result := map[string]string{}
	svc := tags.New(sess)

	// Construct a map from instance-arn -> tag
	var (
		resourceTypeInstance = "ec2:instance"
		resourcesPerPage     = int64(50)
	)
	var groInput tags.GetResourcesInput
	groInput.SetResourceTypeFilters([]*string{&resourceTypeInstance})
	groInput.SetTagFilters([]*tags.TagFilter{
		{Key: &targetTag},
	})
	groInput.SetResourcesPerPage(int64(resourcesPerPage))
	err := svc.GetResourcesPages(&groInput, func(gro *tags.GetResourcesOutput, b bool) bool {
		// This fn gets called once for every page of output.
		// Iterate through the tag map list and record instance -> tag values for our targetTag.
		for _, rtml := range gro.ResourceTagMappingList {
			for _, tag := range rtml.Tags {
				if *tag.Key == targetTag {
					// Split on "/" since ARN looks like:
					// arn:aws:ec2:ap-southeast-2:062921715532:instance/i-009156459674d2df0
					instanceId := strings.Split(*rtml.ResourceARN, "/")[1]
					result[instanceId] = *tag.Value
				}
			}
		}
		return true // Consume all pages
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func getInstancePrimaryIP(sess *session.Session, instanceId string) (string, error) {
	svc := ec2.New(sess)
	var input ec2.DescribeInstancesInput
	input.SetInstanceIds([]*string{&instanceId})
	output, err := svc.DescribeInstances(&input)
	if err != nil {
		return "", errors.Wrap(err, "describe instance failed")
	}
	if len(output.Reservations) != 1 {
		return "", errors.Errorf("wrong number of reservations: %v", len(output.Reservations))
	}
	res := output.Reservations[0]
	if len(res.Instances) != 1 {
		return "", errors.Errorf("wrong number of instances: %v", len(res.Instances))
	}
	privateIP := res.Instances[0].PrivateIpAddress
	if privateIP == nil || len(*privateIP) == 0 {
		return "", errors.Errorf("no private ip found")
	}
	return *privateIP, nil
}
