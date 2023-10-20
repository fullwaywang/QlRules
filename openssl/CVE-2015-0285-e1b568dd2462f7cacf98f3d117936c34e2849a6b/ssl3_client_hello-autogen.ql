/**
 * @name openssl-e1b568dd2462f7cacf98f3d117936c34e2849a6b-ssl3_client_hello
 * @id cpp/openssl/e1b568dd2462f7cacf98f3d117936c34e2849a6b/ssl3-client-hello
 * @description openssl-e1b568dd2462f7cacf98f3d117936c34e2849a6b-ssl3_client_hello CVE-2015-0285
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vp_652, Parameter vs_649) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ssl_fill_hello_random")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vs_649
		and target_2.getArgument(1).(Literal).getValue()="0"
		and target_2.getArgument(2).(VariableAccess).getTarget()=vp_652
		and target_2.getArgument(3).(SizeofExprOperator).getValue()="32")
}

predicate func_4(Variable vi_653) {
	exists(ExprStmt target_4 |
		target_4.getExpr() instanceof FunctionCall
		and target_4.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vi_653)
}

from Function func, Variable vp_652, Variable vi_653, Parameter vs_649
where
func_2(vp_652, vs_649)
and func_4(vi_653)
and vp_652.getType().hasName("unsigned char *")
and vi_653.getType().hasName("int")
and vs_649.getType().hasName("SSL *")
and vp_652.getParentScope+() = func
and vi_653.getParentScope+() = func
and vs_649.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
