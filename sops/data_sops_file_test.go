package sops

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const configTestDataSourceSopsFile_basic = `
data "sops_file" "test_basic" {
  source_file = "%s/test-fixtures/basic.yaml"
}`

func TestDataSourceSopsFile_basic(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(configTestDataSourceSopsFile_basic, wd)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_basic", "data.hello", "world"),
					resource.TestCheckResourceAttr("data.sops_file.test_basic", "data.integer", "0"),
					resource.TestCheckResourceAttr("data.sops_file.test_basic", "data.float", "0.2"),
					resource.TestCheckResourceAttr("data.sops_file.test_basic", "data.bool", "true"),
					resource.TestCheckResourceAttr("data.sops_file.test_basic", "data.null_value", "null"),
				),
			},
		},
	})
}

const configTestDataSourceSopsFile_nested = `
data "sops_file" "test_nested" {
  source_file = "%s/test-fixtures/nested.yaml"
}`

func TestDataSourceSopsFile_nested(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(configTestDataSourceSopsFile_nested, wd)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_nested", "data.db.user", "foo"),
					resource.TestCheckResourceAttr("data.sops_file.test_nested", "data.db.password", "bar"),
				),
			},
		},
	})
}

const configTestDataSourceSopsFile_raw = `
data "sops_file" "test_raw" {
  source_file = "%s/test-fixtures/raw.txt"
  input_type = "raw"
}`

func TestDataSourceSopsFile_raw(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(configTestDataSourceSopsFile_raw, wd)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_raw", "raw", "Hello raw world!"),
				),
			},
		},
	})
}

const configTestDataSourceSopsFile_simplelist = `
data "sops_file" "test_list" {
  source_file = "%s/test-fixtures/simple-list.yaml"
}`

func TestDataSourceSopsFile_simplelist(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(configTestDataSourceSopsFile_simplelist, wd)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.0", "val1"),
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.1", "val2"),
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.2", "null"),
				),
			},
		},
	})
}

const configTestDataSourceSopsFile_complexlist = `
data "sops_file" "test_list" {
  source_file = "%s/test-fixtures/complex-list.yaml"
}`

func TestDataSourceSopsFile_complexlist(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(configTestDataSourceSopsFile_complexlist, wd)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.0.name", "foo"),
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.0.index", "0"),
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.0.value", "null"),
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.1.name", "bar"),
					resource.TestCheckResourceAttr("data.sops_file.test_list", "data.a_list.1.index", "1"),
				),
			},
		},
	})
}

const configTestDataSourceSopsFile_json = `
data "sops_file" "test_json" {
  source_file = "%s/test-fixtures/basic.json"
}`

func TestDataSourceSopsFile_json(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(configTestDataSourceSopsFile_json, wd)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.test_json", "data.hello", "world"),
					resource.TestCheckResourceAttr("data.sops_file.test_json", "data.integer", "0"),
					resource.TestCheckResourceAttr("data.sops_file.test_json", "data.float", "0.2"),
					resource.TestCheckResourceAttr("data.sops_file.test_json", "data.bool", "true"),
					resource.TestCheckResourceAttr("data.sops_file.test_json", "data.null", "null"),
				),
			},
		},
	})
}

const configTestDataSourceSopsFile_undecryptable = `
data "sops_file" "test_undecryptable" {
  source_file = "%s/test-fixtures/undecryptable.yaml"
}`

// A failure must say which key could not be used and why. sops reports that
// through UserError; its plain Error only gives a count of successful key
// groups, which is not enough to tell a missing key from a rejected credential.
func TestDataSourceSopsFile_undecryptableReportsCause(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      fmt.Sprintf(configTestDataSourceSopsFile_undecryptable, wd),
				ExpectError: regexp.MustCompile(`(?s)0000000000000000000000000000000000000000.*FAILED`),
			},
		},
	})
}
