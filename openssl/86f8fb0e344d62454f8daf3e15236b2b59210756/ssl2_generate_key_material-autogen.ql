/**
 * @name openssl-86f8fb0e344d62454f8daf3e15236b2b59210756-ssl2_generate_key_material
 * @id cpp/openssl/86f8fb0e344d62454f8daf3e15236b2b59210756/ssl2-generate-key-material
 * @description openssl-86f8fb0e344d62454f8daf3e15236b2b59210756-ssl2_generate_key_material CVE-2015-0293
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="s->session->master_key_length >= 0 && s->session->master_key_length < (int)sizeof(s->session->master_key)"
		and not target_0.getValue()="s->session->master_key_length >= 0 && s->session->master_key_length <= (int)sizeof(s->session->master_key)"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vs_456) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="master_key_length"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_456
		and target_1.getGreaterOperand() instanceof SizeofExprOperator
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="master_key_length"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_456
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal)
}

predicate func_2(Parameter vs_456) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="master_key_length"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_456)
}

predicate func_3(Function func) {
	exists(SizeofExprOperator target_3 |
		target_3.getValue()="48"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vs_456) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(PointerFieldAccess).getTarget().getName()="master_key_length"
		and target_4.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_4.getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_456
		and target_4.getGreaterOperand() instanceof SizeofExprOperator
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="master_key_length"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session"
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_456
		and target_4.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal)
}

from Function func, Parameter vs_456
where
func_0(func)
and not func_1(vs_456)
and func_2(vs_456)
and func_3(func)
and func_4(vs_456)
and vs_456.getType().hasName("SSL *")
and vs_456.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
