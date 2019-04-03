
import bisect

timestamps = [1,2,4,5]
index = bisect.bisect_right(timestamps, 3)
print(timestamps[index-1])