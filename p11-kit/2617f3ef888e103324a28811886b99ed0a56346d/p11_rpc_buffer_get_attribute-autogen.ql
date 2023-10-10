/**
 * @name p11-kit-2617f3ef888e103324a28811886b99ed0a56346d-p11_rpc_buffer_get_attribute
 * @id cpp/p11-kit/2617f3ef888e103324a28811886b99ed0a56346d/p11-rpc-buffer-get-attribute
 * @description p11-kit-2617f3ef888e103324a28811886b99ed0a56346d-p11-kit/rpc-message.c-p11_rpc_buffer_get_attribute CVE-2020-29363
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vattr_1214, NotExpr target_4, ExprStmt target_3) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint32_t")
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="ulValueLen"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1214
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlength_1216, NotExpr target_4, AddressOfExpr target_5, ExprStmt target_3) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("uint32_t")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1216
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vattr_1214, Variable vlength_1216, NotExpr target_4, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ulValueLen"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1214
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlength_1216
		and target_3.getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(Parameter vattr_1214, NotExpr target_4) {
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="pValue"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1214
}

predicate func_5(Variable vlength_1216, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vlength_1216
}

from Function func, Parameter vattr_1214, Variable vlength_1216, ExprStmt target_3, NotExpr target_4, AddressOfExpr target_5
where
not func_1(vattr_1214, target_4, target_3)
and not func_2(vlength_1216, target_4, target_5, target_3)
and func_3(vattr_1214, vlength_1216, target_4, target_3)
and func_4(vattr_1214, target_4)
and func_5(vlength_1216, target_5)
and vattr_1214.getType().hasName("CK_ATTRIBUTE *")
and vlength_1216.getType().hasName("uint32_t")
and vattr_1214.getParentScope+() = func
and vlength_1216.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
