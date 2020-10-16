package crc645bd5184c13cc5d7e;


public class WebAuthenticationCallbackActivity
	extends crc64a0e0a82d0db9a07d.WebAuthenticatorCallbackActivity
	implements
		mono.android.IGCUserPeer
{
/** @hide */
	public static final String __md_methods;
	static {
		__md_methods = 
			"";
		mono.android.Runtime.register ("OktaAuth.Droid.WebAuthenticationCallbackActivity, OktaAuth.Android", WebAuthenticationCallbackActivity.class, __md_methods);
	}


	public WebAuthenticationCallbackActivity ()
	{
		super ();
		if (getClass () == WebAuthenticationCallbackActivity.class)
			mono.android.TypeManager.Activate ("OktaAuth.Droid.WebAuthenticationCallbackActivity, OktaAuth.Android", "", this, new java.lang.Object[] {  });
	}

	private java.util.ArrayList refList;
	public void monodroidAddReference (java.lang.Object obj)
	{
		if (refList == null)
			refList = new java.util.ArrayList ();
		refList.add (obj);
	}

	public void monodroidClearReferences ()
	{
		if (refList != null)
			refList.clear ();
	}
}
