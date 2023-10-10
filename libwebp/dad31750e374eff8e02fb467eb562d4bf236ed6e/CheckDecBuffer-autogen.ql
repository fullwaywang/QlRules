/**
 * @name libwebp-dad31750e374eff8e02fb467eb562d4bf236ed6e-CheckDecBuffer
 * @id cpp/libwebp/dad31750e374eff8e02fb467eb562d4bf236ed6e/CheckDecBuffer
 * @description libwebp-dad31750e374eff8e02fb467eb562d4bf236ed6e-src/dec/buffer_dec.c-CheckDecBuffer CVE-2020-36328
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmode_43, Variable vwidth_44, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vwidth_44
		and target_0.getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const uint8_t[13]")
		and target_0.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vmode_43
		and target_2.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignAndExpr).getRValue().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignAndExpr).getRValue().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwidth_44, VariableAccess target_1) {
		target_1.getTarget()=vwidth_44
}

predicate func_2(Variable vmode_43, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vmode_43
}

predicate func_3(Variable vmode_43, Variable vwidth_44, ExprStmt target_3) {
		target_3.getExpr().(AssignAndExpr).getRValue().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_44
		and target_3.getExpr().(AssignAndExpr).getRValue().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vmode_43
}

predicate func_4(Variable vwidth_44, ExprStmt target_4) {
		target_4.getExpr().(AssignAndExpr).getRValue().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vwidth_44
}

from Function func, Variable vmode_43, Variable vwidth_44, VariableAccess target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vmode_43, vwidth_44, target_2, target_3, target_4)
and func_1(vwidth_44, target_1)
and func_2(vmode_43, target_2)
and func_3(vmode_43, vwidth_44, target_3)
and func_4(vwidth_44, target_4)
and vmode_43.getType().hasName("const WEBP_CSP_MODE")
and vwidth_44.getType().hasName("const int")
and vmode_43.getParentScope+() = func
and vwidth_44.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
