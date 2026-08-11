package grpcclient

import (
	"reflect"
	"testing"
)

func TestRingbufPushPopOrderWithinCapacity(t *testing.T) {
	t.Parallel()

	q := newRingbuf[int](5)
	q.push(10)
	q.push(20)
	q.push(30)

	got := make([]int, 3)
	n := q.pop(3, got)

	if n != 3 {
		t.Fatalf("expected 3 items, got %d", n)
	}
	want := []int{10, 20, 30}
	if !reflect.DeepEqual(got[:n], want) {
		t.Fatalf("unexpected pop result: got %v want %v", got[:n], want)
	}
}

func TestRingbufPushDropsOldestWhenFull(t *testing.T) {
	t.Parallel()

	q := newRingbuf[int](3)
	q.push(1)
	q.push(2)
	q.push(3)
	q.push(4) // 1 is dropped

	got := make([]int, 3)
	n := q.pop(3, got)

	if n != 3 {
		t.Fatalf("expected 3 items, got %d", n)
	}
	want := []int{2, 3, 4}
	if !reflect.DeepEqual(got[:n], want) {
		t.Fatalf("unexpected pop result: got %v want %v", got[:n], want)
	}
}

func TestRingbufPopWrapAroundOrder(t *testing.T) {
	t.Parallel()

	q := newRingbuf[int](5)
	for i := 1; i <= 5; i++ {
		q.push(i)
	}

	first := make([]int, 3)
	n := q.pop(3, first)
	if n != 3 {
		t.Fatalf("expected 3 items in first pop, got %d", n)
	}
	if !reflect.DeepEqual(first[:n], []int{1, 2, 3}) {
		t.Fatalf("unexpected first pop result: got %v want %v", first[:n], []int{1, 2, 3})
	}

	q.push(6)
	q.push(7)
	q.push(8)

	second := make([]int, 5)
	n = q.pop(5, second)
	if n != 5 {
		t.Fatalf("expected 5 items in second pop, got %d", n)
	}
	want := []int{4, 5, 6, 7, 8}
	if !reflect.DeepEqual(second[:n], want) {
		t.Fatalf("unexpected second pop result: got %v want %v", second[:n], want)
	}
}

func TestRingbufPopCountCappedByLength(t *testing.T) {
	t.Parallel()

	q := newRingbuf[int](4)
	q.push(11)
	q.push(12)

	got := make([]int, 4)
	n := q.pop(4, got)

	if n != 2 {
		t.Fatalf("expected 2 items, got %d", n)
	}
	want := []int{11, 12}
	if !reflect.DeepEqual(got[:n], want) {
		t.Fatalf("unexpected pop result: got %v want %v", got[:n], want)
	}
}
