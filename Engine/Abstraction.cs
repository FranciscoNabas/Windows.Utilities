using System;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Windows.Utilities
{
    [Serializable()]
    public class InvalidObjectStateException : Exception
    {
        protected InvalidObjectStateException(SerializationInfo info, StreamingContext context) : base(info, context) { }

        public InvalidObjectStateException() : base() { }
        public InvalidObjectStateException(string message) : base(message) { }
        public InvalidObjectStateException(string message, Exception innerException) : base(message, innerException) { }
    }

    [Serializable()]
    public class NativeException : Exception
    {
        private int _native_error_number;
        private string? _stack_trace;

        public override string StackTrace
        {
            get
            {
                if (_stack_trace is null)
                    return base.StackTrace;

                return _stack_trace;
            }
        }

        public int NativeErrorNumber
        {
            get
            {
                return _native_error_number;
            }
            set
            {
                _native_error_number = value;
            }
        }

        protected NativeException() : base() { }

        protected NativeException(SerializationInfo info, StreamingContext context) : base(info, context) { }

        public NativeException(int error_number) :
            base(string.Format("Native exception. Function set error '{0}'.", error_number))
        {
            _native_error_number = error_number;
        }

        public NativeException(int error_code, string message) :
            base(message)
        {
            _native_error_number= error_code;
        }

        public NativeException(int error_code, string message, Exception inner_exception) :
            base(message, inner_exception)
        {
            _native_error_number = error_code;
        }

        public static void ThrowNativeException(int error_code, string stack_trace)
        {
            NativeException ex = new(error_code, Base.GetSystemErrorText(error_code))
            {
                _stack_trace = stack_trace
            };
            throw ex;
        }
    }

    public abstract class Enumeration : IComparable
    {
        public uint Id { get; set; }
        public string Name { get; set; }

        protected Enumeration(uint id, string name) => (Id, Name) = (id, name);

        public static IEnumerable<T> GetAll<T>() where T : Enumeration =>
            typeof(T).GetFields(BindingFlags.Public |
                                BindingFlags.Static |
                                BindingFlags.DeclaredOnly)
                    .Select(f => f.GetValue(null))
                    .Cast<T>();

        public static T GetById<T>(uint id) where T : Enumeration =>
            GetAll<T>().First(f => f.Id == id);

        public override string ToString() => Name;

        public override int GetHashCode() => (Name, Id).GetHashCode();

        public override bool Equals(object obj)
        {
            if (obj is not Enumeration other_value)
                return false;

            return GetType().Equals(obj.GetType()) && Id.Equals(other_value.Id);
        }

        public int CompareTo(object obj)
        {
            if (obj is null)
                return 0;

            return Id.CompareTo(((Enumeration)obj).Id);
        }

        public static implicit operator uint(Enumeration value) => value.Id;
        public static uint operator | (Enumeration left, Enumeration right)
        {
            return left.Id | right.Id;
        }
    }
}
