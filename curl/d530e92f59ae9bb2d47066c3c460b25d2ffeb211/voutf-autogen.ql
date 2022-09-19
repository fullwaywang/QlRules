import cpp

from Function func, Variable vcut
where
vcut.getType().hasName("size_t")
and vcut.getParentScope+() = func
select func, vcut
