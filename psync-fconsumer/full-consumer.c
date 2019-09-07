/*

This is a psync full consumer implementation 
Details: https://redmine.named-data.net/issues/4987

*/

#include "../face/dummy-face.h"

typedef struct
{

    void (*init_full_consumer);        
    void (*send_sync_interet);
    void (*on_sync_data);
    void (*stop);
    

} full_consumer;

void init_full_consumer()
{
}


void send_sync_interet() 
{
}

void on_sync_data()
{
}
