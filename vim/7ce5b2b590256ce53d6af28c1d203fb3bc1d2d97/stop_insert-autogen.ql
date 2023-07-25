/**
 * @name vim-7ce5b2b590256ce53d6af28c1d203fb3bc1d2d97-stop_insert
 * @id cpp/vim/7ce5b2b590256ce53d6af28c1d203fb3bc1d2d97/stop-insert
 * @description vim-7ce5b2b590256ce53d6af28c1d203fb3bc1d2d97-src/edit.c-stop_insert CVE-2022-1735
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("check_visual_pos")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vVIsual_active, BlockStmt target_7, VariableAccess target_1) {
		target_1.getTarget()=vVIsual_active
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_2(Variable vcurwin, Variable vVIsual_active, Variable vVIsual, BlockStmt target_7, LogicalAndExpr target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vVIsual_active
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vVIsual
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_2.getParent().(IfStmt).getThen()=target_7
}

predicate func_3(LogicalAndExpr target_2, Function func, DeclStmt target_3) {
		target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vVIsual, Variable vlen_2546, LogicalAndExpr target_2, IfStmt target_4) {
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vVIsual
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_2546
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vVIsual
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_2546
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vVIsual
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

/*predicate func_5(Variable vVIsual, Variable vlen_2546, AssignExpr target_5) {
		target_5.getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_5.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vVIsual
		and target_5.getRValue().(VariableAccess).getTarget()=vlen_2546
}

*/
/*predicate func_6(Variable vVIsual, RelationalOperation target_8, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vVIsual
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
predicate func_7(BlockStmt target_7) {
		target_7.getStmt(1) instanceof IfStmt
}

predicate func_8(Variable vlen_2546, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand() instanceof ValueFieldAccess
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vlen_2546
}

from Function func, Variable vcurwin, Variable vVIsual_active, Variable vVIsual, Variable vlen_2546, VariableAccess target_1, LogicalAndExpr target_2, DeclStmt target_3, IfStmt target_4, BlockStmt target_7, RelationalOperation target_8
where
not func_0(func)
and func_1(vVIsual_active, target_7, target_1)
and func_2(vcurwin, vVIsual_active, vVIsual, target_7, target_2)
and func_3(target_2, func, target_3)
and func_4(vVIsual, vlen_2546, target_2, target_4)
and func_7(target_7)
and func_8(vlen_2546, target_8)
and vcurwin.getType().hasName("win_T *")
and vVIsual_active.getType().hasName("int")
and vVIsual.getType().hasName("pos_T")
and vlen_2546.getType().hasName("int")
and not vcurwin.getParentScope+() = func
and not vVIsual_active.getParentScope+() = func
and not vVIsual.getParentScope+() = func
and vlen_2546.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
