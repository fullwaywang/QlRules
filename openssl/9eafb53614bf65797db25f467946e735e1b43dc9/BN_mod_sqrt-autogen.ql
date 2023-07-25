/**
 * @name openssl-9eafb53614bf65797db25f467946e735e1b43dc9-BN_mod_sqrt
 * @id cpp/openssl/9eafb53614bf65797db25f467946e735e1b43dc9/BN-mod-sqrt
 * @description openssl-9eafb53614bf65797db25f467946e735e1b43dc9-BN_mod_sqrt CVE-2022-0778
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof FunctionCall
		and target_2.getThen().(BreakStmt).toString() = "break;"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable ve_24, Variable vi_24) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_24
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=ve_24
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="3"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="111"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

predicate func_4(Variable vi_24) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_24
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_5(Parameter vp_13, Parameter vctx_13, Variable vb_23, Variable vt_23) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_sqr")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_23
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vb_23
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_13
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctx_13
		and target_5.getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_6(Variable vt_23) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("BN_is_one")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vt_23)
}

predicate func_7(Variable vi_24) {
	exists(PostfixIncrExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vi_24)
}

predicate func_8(Parameter vp_13, Parameter vctx_13, Variable vt_23) {
	exists(IfStmt target_8 |
		target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_mod_mul")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_23
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt_23
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vt_23
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_13
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vctx_13
		and target_8.getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_11(Variable ve_24, Variable vi_24) {
	exists(WhileStmt target_11 |
		target_11.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_11.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof PostfixIncrExpr
		and target_11.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_24
		and target_11.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=ve_24
		and target_11.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="3"
		and target_11.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="111"
		and target_11.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_11.getStmt().(BlockStmt).getStmt(2) instanceof IfStmt)
}

predicate func_13(Variable vq_23, Variable ve_24) {
	exists(NotExpr target_13 |
		target_13.getOperand().(FunctionCall).getTarget().hasName("BN_rshift")
		and target_13.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_23
		and target_13.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_23
		and target_13.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=ve_24
		and target_13.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_14(Variable vi_24) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(VariableAccess).getTarget()=vi_24
		and target_14.getRValue().(Literal).getValue()="1")
}

from Function func, Parameter vp_13, Parameter vctx_13, Variable vb_23, Variable vq_23, Variable vt_23, Variable ve_24, Variable vi_24
where
not func_2(func)
and not func_3(ve_24, vi_24)
and func_4(vi_24)
and func_5(vp_13, vctx_13, vb_23, vt_23)
and func_6(vt_23)
and func_7(vi_24)
and func_8(vp_13, vctx_13, vt_23)
and func_11(ve_24, vi_24)
and vp_13.getType().hasName("const BIGNUM *")
and vctx_13.getType().hasName("BN_CTX *")
and vb_23.getType().hasName("BIGNUM *")
and vt_23.getType().hasName("BIGNUM *")
and ve_24.getType().hasName("int")
and func_13(vq_23, ve_24)
and vi_24.getType().hasName("int")
and func_14(vi_24)
and vp_13.getParentScope+() = func
and vctx_13.getParentScope+() = func
and vb_23.getParentScope+() = func
and vq_23.getParentScope+() = func
and vt_23.getParentScope+() = func
and ve_24.getParentScope+() = func
and vi_24.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
