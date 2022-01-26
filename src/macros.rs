macro_rules! clone {
    ($($n:ident),+ => async move $body:tt) => (
        {
            $( #[allow(unused_mut)] let mut $n = $n.clone(); )+
            async move $body
        }
    );
}