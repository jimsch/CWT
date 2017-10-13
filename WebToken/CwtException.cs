using System;

namespace Com.AugustCellars.WebToken
{
    public class CwtException : Exception
    {
        public CwtException(string str) : base(str) { }
    }
}
