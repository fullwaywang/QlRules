/**
 * @name openssl-f426625b6ae9a7831010750490a5f0ad689c5ba3-chacha20_poly1305_ctrl
 * @id cpp/openssl/f426625b6ae9a7831010750490a5f0ad689c5ba3/chacha20-poly1305-ctrl
 * @description openssl-f426625b6ae9a7831010750490a5f0ad689c5ba3-crypto/evp/e_chacha20_poly1305.c-chacha20_poly1305_ctrl CVE-2019-1543
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter varg_498, ExprStmt target_4, Literal target_0) {
		target_0.getValue()="16"
		and not target_0.getValue()="12"
		and target_0.getParent().(GTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=varg_498
		and target_0.getParent().(GTExpr).getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_1(Parameter varg_498, VariableAccess target_5, ExprStmt target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=varg_498
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="12"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter varg_498, ReturnStmt target_6, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=varg_498
		and target_2.getGreaterOperand().(Literal).getValue()="0"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=varg_498
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="16"
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

*/
/*predicate func_3(Parameter varg_498, ReturnStmt target_6, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=varg_498
		and target_3.getLesserOperand().(Literal).getValue()="16"
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=varg_498
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_4(Parameter varg_498, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nonce_len"
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=varg_498
}

predicate func_5(Parameter vtype_498, VariableAccess target_5) {
		target_5.getTarget()=vtype_498
}

predicate func_6(ReturnStmt target_6) {
		target_6.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vtype_498, Parameter varg_498, Literal target_0, ExprStmt target_4, VariableAccess target_5, ReturnStmt target_6
where
func_0(varg_498, target_4, target_0)
and not func_1(varg_498, target_5, target_4)
and func_4(varg_498, target_4)
and func_5(vtype_498, target_5)
and func_6(target_6)
and vtype_498.getType().hasName("int")
and varg_498.getType().hasName("int")
and vtype_498.getParentScope+() = func
and varg_498.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
