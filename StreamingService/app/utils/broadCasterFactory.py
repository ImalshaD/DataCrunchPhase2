from broadCaster import BroadCaster

class BroadCasterFactory:
    def __init__(self):
        self.broadcasters = {}
        self.weather_evalpath = "\Datasets\weatherData\eval_data.csv"
        self.weather_testpath = "\Datasets\weatherData\\test_data.csv"
        self.price_evalpath = "\Datasets\priceData\eval_data.csv"
        self.price_testpath = "\Datasets\priceData\\test_data.csv"

        self.broadcasters["weather_test"] = BroadCaster("weather_test", self.weather_evalpath, 30)
        self.broadcasters["price_test"] = BroadCaster("price_test", self.price_evalpath, 30)

    def create_broadcaster(self, key, csv_path, delay=30):
        if key not in self.broadcasters:
            self.broadcasters[key] = BroadCaster(key, csv_path, delay)
        return self.broadcasters[key]

    def get_broadcaster(self, key):
        return self.broadcasters.get(key)

    def remove_broadcaster(self, key):
        if key in self.broadcasters:
            del self.broadcasters[key]
        return None
    