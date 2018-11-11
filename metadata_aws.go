package inkfish

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	tags "github.com/aws/aws-sdk-go/service/resourcegroupstaggingapi"
)

// TODO: This should probably be an expiring cache
var instancePrimaryIPCache map[string]string
var region = "ap-southeast-2"

func UpdateMetadataAWS(cache *MetadataCache) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
	if err != nil {
		// TODO: logging
		return
	}
	instanceToProxyTag, err := InstanceTagLookup(sess, "ProxyUser")
	if err != nil {
		// TODO: logging
		return
	}
	instanceToProxyTag[""] = ""
}

func InstanceTagLookup(sess *session.Session, targetTag string) (map[string]string, error) {
	var result map[string]string
	svc := tags.New(sess)

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
		// This fn gets called once for every page of output
		for _, rtml := range gro.ResourceTagMappingList {
			for _, tag := range rtml.Tags {
				if *tag.Key == targetTag {
					result[*rtml.ResourceARN] = *tag.Value
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func GetInstancePrimaryIP(sess *session.Session, instanceId string) (string, error) {
	//	client := ec2.New(sess)
	//	client.
	return "", nil
}
