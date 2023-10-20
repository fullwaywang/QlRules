/**
 * @name libtiff-b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a-LZWDecode
 * @id cpp/libtiff/b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a/LZWDecode
 * @description libtiff-b4e79bfa0c7d2d08f6f1e7ec38143fc8cb11394a-libtiff/tif_lzw.c-LZWDecode CVE-2022-1622
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_392, EqualityOperation target_2, IfStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="read_error"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_392
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_392, ExprStmt target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="read_error"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_392
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(48)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(48).getFollowingStmt()=target_1)
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsp_392, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="dec_codetab"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_392
		and target_2.getAnOperand() instanceof Literal
}

predicate func_3(Variable vsp_392, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="dec_restart"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_392
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("code_t *")
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="dec_restart"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_392
}

predicate func_4(Variable vsp_392, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dec_maxcodep"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_392
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("code_t *")
}

from Function func, Variable vsp_392, EqualityOperation target_2, IfStmt target_3, ExprStmt target_4
where
not func_0(vsp_392, target_2, target_3, func)
and not func_1(vsp_392, target_4, func)
and func_2(vsp_392, target_2)
and func_3(vsp_392, target_3)
and func_4(vsp_392, target_4)
and vsp_392.getType().hasName("LZWCodecState *")
and vsp_392.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
