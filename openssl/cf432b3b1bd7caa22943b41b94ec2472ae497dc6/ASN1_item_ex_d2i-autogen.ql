/**
 * @name openssl-cf432b3b1bd7caa22943b41b94ec2472ae497dc6-ASN1_item_ex_d2i
 * @id cpp/openssl/cf432b3b1bd7caa22943b41b94ec2472ae497dc6/ASN1-item-ex-d2i
 * @description openssl-cf432b3b1bd7caa22943b41b94ec2472ae497dc6-crypto/asn1/tasn_dec.c-ASN1_item_ex_d2i CVE-2015-3195
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vaclass_167, FunctionCall target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vaclass_167
		and target_0.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="-1025"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignAndExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getArgument(5).(VariableAccess).getLocation()))
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vit_166, Parameter vpval_165, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ASN1_item_ex_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vit_166
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vit_166, Parameter vaclass_167, Parameter vpval_165, FunctionCall target_3) {
		target_3.getTarget().hasName("asn1_d2i_ex_primitive")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vpval_165
		and target_3.getArgument(3).(VariableAccess).getTarget()=vit_166
		and target_3.getArgument(5).(VariableAccess).getTarget()=vaclass_167
}

from Function func, Parameter vit_166, Parameter vaclass_167, Parameter vpval_165, ExprStmt target_2, FunctionCall target_3
where
not func_0(vaclass_167, target_3, func)
and not func_1(func)
and func_2(vit_166, vpval_165, func, target_2)
and func_3(vit_166, vaclass_167, vpval_165, target_3)
and vit_166.getType().hasName("const ASN1_ITEM *")
and vaclass_167.getType().hasName("int")
and vpval_165.getType().hasName("ASN1_VALUE **")
and vit_166.getParentScope+() = func
and vaclass_167.getParentScope+() = func
and vpval_165.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
