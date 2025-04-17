# load_data.py
import pandas as pd

def load_grouped_data(csv_path):
    df = pd.read_csv(csv_path)
    df['Date'] = df['Date'].astype(str)
    grouped = df.groupby('Date')
    date_batches = {
        date: group.to_dict(orient='records')
        for date, group in grouped
    }
    return date_batches