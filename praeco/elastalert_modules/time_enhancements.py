import datetime
import dateutil
import dateutil.tz

from elastalert.util import ts_to_dt
from elastalert.util import elastalert_logger
from elastalert.enhancements import BaseEnhancement


class CustomTimeEnhancement(BaseEnhancement):

    def process(self, match):
        if '@timestamp' in match:
            ts = match['@timestamp']
            if isinstance(ts, str) and ts.endswith('Z'):
                match['@localtime'] = self._pretty_ts(ts)


    def _pretty_ts(self, timestamp, tz=True):
        dt = timestamp
        if not isinstance(timestamp, datetime.datetime):
            dt = ts_to_dt(timestamp)
            if tz:
                dt = dt.astimezone(dateutil.tz.gettz('Asia/Seoul'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
