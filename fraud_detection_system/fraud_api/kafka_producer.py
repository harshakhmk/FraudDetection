from confluent_kafka import Producer

producer = Producer({'bootstrap.servers': 'localhost:9092'})

def produce_message(topic, message):
    producer.produce(topic, message)
    producer.flush()