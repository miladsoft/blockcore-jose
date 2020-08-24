namespace Jose
{
    public class JSSerializerMapper : IJsonMapper
    {
        private static NewtonsoftMapper js;

        private NewtonsoftMapper JS
        {
            get { return js ?? (js = new NewtonsoftMapper()); }
        }

        public string Serialize(object obj)
        {
            return JS.Serialize(obj);
        }

        public T Parse<T>(string json)
        {
            return JS.Parse<T>(json);
        }
    }
}