package main

import (
	"reflect"
	"testing"
)

func TestWantsHelp(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"update", "--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"update", "ep-1"}, false},
		{[]string{"ep-1", "--", "ls", "-h"}, false},
	} {
		if got := wantsHelp(c.args); got != c.want {
			t.Errorf("wantsHelp(%v) = %v", c.args, got)
		}
	}
}

func TestAgentUpdateBody(t *testing.T) {
	ok := []struct {
		args []string
		want map[string]interface{}
	}{
		{[]string{"ep-1"}, map[string]interface{}{"endpoint_ids": []string{"ep-1"}, "version": ""}},
		{[]string{"ep-1", "1.8.82"}, map[string]interface{}{"endpoint_ids": []string{"ep-1"}, "version": "1.8.82"}},
		{[]string{"ep-1", "ep-2", "--version", "1.8.82"}, map[string]interface{}{"endpoint_ids": []string{"ep-1", "ep-2"}, "version": "1.8.82"}},
		{[]string{"ep-1,ep-2", "ep-3"}, map[string]interface{}{"endpoint_ids": []string{"ep-1", "ep-2", "ep-3"}, "version": ""}},
		{[]string{"all", "--version=1.8.82"}, map[string]interface{}{"all": true, "version": "1.8.82"}},
	}
	for _, c := range ok {
		got, err := agentUpdateBody(c.args)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: %v %v", c.args, got, err)
		}
	}
	for _, bad := range [][]string{{}, {"--help"}, {"--bogus", "ep-1"}, {"all", "ep-1"}, {"--version", "1.8.82"}} {
		if _, err := agentUpdateBody(bad); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
}
