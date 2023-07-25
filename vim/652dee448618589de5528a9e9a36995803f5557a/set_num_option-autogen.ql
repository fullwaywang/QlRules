/**
 * @name vim-652dee448618589de5528a9e9a36995803f5557a-set_num_option
 * @id cpp/vim/652dee448618589de5528a9e9a36995803f5557a/set-num-option
 * @description vim-652dee448618589de5528a9e9a36995803f5557a-src/option.c-set_num_option CVE-2022-0417
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ve_invalid_argument, Variable verrmsg_3314, Variable vcurbuf, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="b_p_ts"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="9999"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_3314
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invalid_argument
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="b_p_ts"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="8"
		and target_0.getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcurbuf, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="b_p_ts"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_1.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_2(Variable ve_invalid_argument, Variable verrmsg_3314, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_3314
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invalid_argument
}

predicate func_3(Variable verrmsg_3314, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_3314
}

predicate func_4(Variable vcurbuf, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="b_p_ts"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurbuf
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="8"
}

from Function func, Variable ve_invalid_argument, Variable verrmsg_3314, Variable vcurbuf, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(ve_invalid_argument, verrmsg_3314, vcurbuf, target_1, target_2, target_3, target_4)
and func_1(vcurbuf, target_1)
and func_2(ve_invalid_argument, verrmsg_3314, target_2)
and func_3(verrmsg_3314, target_3)
and func_4(vcurbuf, target_4)
and ve_invalid_argument.getType() instanceof ArrayType
and verrmsg_3314.getType().hasName("char *")
and vcurbuf.getType().hasName("buf_T *")
and not ve_invalid_argument.getParentScope+() = func
and verrmsg_3314.getParentScope+() = func
and not vcurbuf.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
