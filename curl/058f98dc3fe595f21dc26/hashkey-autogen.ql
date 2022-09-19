import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="%ld%s"
		and not target_0.getValue()="%u/%ld/%s"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vconn) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="scope_id"
		and target_1.getType().hasName("unsigned int")
		and target_1.getQualifier().(VariableAccess).getTarget()=vconn)
}

from Function func, Parameter vconn
where
func_0(func)
and not func_1(vconn)
and vconn.getType().hasName("connectdata *")
and vconn.getParentScope+() = func
select func, vconn
