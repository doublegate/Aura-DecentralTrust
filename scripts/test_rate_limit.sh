#!/bin/bash
# Test rate limiting functionality

echo "🧪 Testing rate limiting on Aura Node API..."

# Base URL
BASE_URL="http://localhost:8080"

# Test rate limit (default: 60 requests per minute)
echo "📊 Sending 65 requests to test rate limiting..."
echo "   (Rate limit should trigger after 60 requests)"

# Counter for successful requests
SUCCESS=0
RATE_LIMITED=0

# Send 65 requests rapidly
for i in {1..65}; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/")
    
    if [ "$RESPONSE" == "200" ]; then
        ((SUCCESS++))
        echo -n "."
    elif [ "$RESPONSE" == "429" ]; then
        ((RATE_LIMITED++))
        echo -n "X"
    else
        echo -n "?"
    fi
    
    # Small delay to avoid overwhelming
    sleep 0.01
done

echo ""
echo ""
echo "📈 Results:"
echo "   ✅ Successful requests: $SUCCESS"
echo "   🚫 Rate limited (429): $RATE_LIMITED"
echo ""

if [ $RATE_LIMITED -gt 0 ]; then
    echo "✅ Rate limiting is working correctly!"
else
    echo "⚠️  Rate limiting may not be working. Check configuration."
fi

echo ""
echo "💡 Tips:"
echo "   - Default rate limit: 60 requests/minute"
echo "   - Configure in config.toml under [security]"
echo "   - Set rate_limit_rpm and rate_limit_rph"