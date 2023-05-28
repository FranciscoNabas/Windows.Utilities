using System;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;

namespace Windows.Utilities
{
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
