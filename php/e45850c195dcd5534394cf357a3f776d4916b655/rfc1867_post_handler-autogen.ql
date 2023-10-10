/**
 * @name php-e45850c195dcd5534394cf357a3f776d4916b655-rfc1867_post_handler
 * @id cpp/php/e45850c195dcd5534394cf357a3f776d4916b655/rfc1867-post-handler
 * @description php-e45850c195dcd5534394cf357a3f776d4916b655-main/rfc1867.c-rfc1867_post_handler CVE-2023-0662
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vupload_cnt_689, RelationalOperation target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vupload_cnt_689
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vupload_cnt_689
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsapi_module, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="sapi_error"
		and target_1.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsapi_module
		and target_1.getExpr().(VariableCall).getArgument(0).(BinaryBitwiseOperation).getValue()="2"
		and target_1.getExpr().(VariableCall).getArgument(1).(StringLiteral).getValue()="Maximum number of allowable file uploads has been exceeded"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vupload_cnt_689, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vupload_cnt_689
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vupload_cnt_689, ExprStmt target_3) {
		target_3.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vupload_cnt_689
}

from Function func, Variable vupload_cnt_689, Variable vsapi_module, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3
where
not func_0(vupload_cnt_689, target_2, target_3)
and func_1(vsapi_module, target_2, target_1)
and func_2(vupload_cnt_689, target_2)
and func_3(vupload_cnt_689, target_3)
and vupload_cnt_689.getType().hasName("int")
and vsapi_module.getType().hasName("sapi_module_struct")
and vupload_cnt_689.getParentScope+() = func
and not vsapi_module.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
