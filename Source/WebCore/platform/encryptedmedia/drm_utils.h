#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Macros to track the value of API success or failure
 */
#define DRM_API_SUCCESS (0)
#define DRM_API_FAILED  (-1)

/**
 * @class DrmData
 * @brief To hold DRM key, license request etc.
 */
class DrmData{

private:
        unsigned char *data;
        int dataLength;
public:

        DrmData();
        DrmData(unsigned char *data, int dataLength);
        DrmData(const DrmData&) = delete;
        DrmData& operator=(const DrmData&) = delete;
        ~DrmData();

        unsigned char * getData();

        int getDataLength();

        void setData(unsigned char * data, int dataLength);

        void addData(unsigned char * data, int dataLength);

};
