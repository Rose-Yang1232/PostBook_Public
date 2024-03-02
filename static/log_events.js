console.log('Click event triggered');
$(document).ready(function() {
    $(document).click(function(event) {
        console.log('Click event triggered');
        console.log('Prefix is:', prefix);
        console.log('URL for POST request:', prefix + '/log_event');
        console.log('URL for POST request:', '/log_event');
        var clickData = {
            type: 'click',
            x: event.pageX,
            y: event.pageY,
            url: window.location.href, // Add the current URL
            timestamp: (new Date).getTime() // get the current timestamp
        };
        $.ajax({
            url: window.location.origin + '/' + prefix + '/log_event', // Correctly construct the URL with the prefix
            // url:'/log_event',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(clickData),
            success: function(response) {
                console.log('Event logged:', response);
            },
            error: function(xhr, status, error) {
                console.error('Error logging event:', xhr.responseText);
            }
        });
        
        // $.ajax({
        //     url: window.location.origin + prefix + '/log_event',
        //     type: 'POST',
        //     contentType: 'application/json',
        //     data: JSON.stringify(clickData)
        // });
    });

    $(document).keypress(function(event) {
        var keyData = {
            type: 'keypress',
            key: String.fromCharCode(event.which),
            url: window.location.href, // Add the current URL
            timestamp: (new Date).getTime()
        };
        $.ajax({
            url: window.location.origin + '/' + prefix + '/log_event', 
            // url:'/log_event',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(keyData)
        });
    });
});

