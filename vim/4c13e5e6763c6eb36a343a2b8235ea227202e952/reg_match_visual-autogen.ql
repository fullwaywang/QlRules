/**
 * @name vim-4c13e5e6763c6eb36a343a2b8235ea227202e952-reg_match_visual
 * @id cpp/vim/4c13e5e6763c6eb36a343a2b8235ea227202e952/reg-match-visual
 * @description vim-4c13e5e6763c6eb36a343a2b8235ea227202e952-src/regexp.c-reg_match_visual CVE-2021-4192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrex, ValueFieldAccess target_8) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(ValueFieldAccess).getTarget().getName()="line"
		and target_0.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getRValue().(FunctionCall).getTarget().hasName("reg_getline")
		and target_0.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="lnum"
		and target_0.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_8.getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcol_1267, Variable vrex, EqualityOperation target_9, PointerArithmeticOperation target_7) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="input"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_1.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand() instanceof ValueFieldAccess
		and target_1.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcol_1267
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_7.getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcol_1267, Variable vwp_1268, Variable vrex, Variable vcols_1272, EqualityOperation target_9, LogicalOrExpr target_10, ExprStmt target_11, LogicalOrExpr target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcols_1272
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("win_linetabsize")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_1268
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="line"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcol_1267
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vcol_1267, Variable vrex, EqualityOperation target_13, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcol_1267
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="input"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="line"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_5(Variable vrex, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="line"
		and target_5.getQualifier().(VariableAccess).getTarget()=vrex
}

predicate func_6(Variable vrex, VariableAccess target_6) {
		target_6.getTarget()=vrex
}

predicate func_7(Variable vwp_1268, Variable vrex, ExprStmt target_11, PointerArithmeticOperation target_7) {
		target_7.getLeftOperand().(ValueFieldAccess).getTarget().getName()="input"
		and target_7.getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_7.getRightOperand() instanceof ValueFieldAccess
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("win_linetabsize")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_1268
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="line"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_8(Variable vrex, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="line"
		and target_8.getQualifier().(VariableAccess).getTarget()=vrex
}

predicate func_9(EqualityOperation target_9) {
		target_9.getAnOperand().(Literal).getValue()="22"
}

predicate func_10(Variable vcol_1267, LogicalOrExpr target_10) {
		target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcol_1267
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcol_1267
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="101"
}

predicate func_11(Variable vwp_1268, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("getvvcol")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vwp_1268
		and target_11.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_12(Variable vcols_1272, LogicalOrExpr target_12) {
		target_12.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcols_1272
		and target_12.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcols_1272
		and target_12.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="101"
}

predicate func_13(EqualityOperation target_13) {
		target_13.getAnOperand().(CharLiteral).getValue()="118"
}

from Function func, Variable vcol_1267, Variable vwp_1268, Variable vrex, Variable vcols_1272, ExprStmt target_4, ValueFieldAccess target_5, VariableAccess target_6, PointerArithmeticOperation target_7, ValueFieldAccess target_8, EqualityOperation target_9, LogicalOrExpr target_10, ExprStmt target_11, LogicalOrExpr target_12, EqualityOperation target_13
where
not func_0(vrex, target_8)
and not func_1(vcol_1267, vrex, target_9, target_7)
and not func_2(vcol_1267, vwp_1268, vrex, vcols_1272, target_9, target_10, target_11, target_12)
and func_4(vcol_1267, vrex, target_13, target_4)
and func_5(vrex, target_5)
and func_6(vrex, target_6)
and func_7(vwp_1268, vrex, target_11, target_7)
and func_8(vrex, target_8)
and func_9(target_9)
and func_10(vcol_1267, target_10)
and func_11(vwp_1268, target_11)
and func_12(vcols_1272, target_12)
and func_13(target_13)
and vcol_1267.getType().hasName("colnr_T")
and vwp_1268.getType().hasName("win_T *")
and vrex.getType().hasName("regexec_T")
and vcols_1272.getType().hasName("colnr_T")
and vcol_1267.getParentScope+() = func
and vwp_1268.getParentScope+() = func
and not vrex.getParentScope+() = func
and vcols_1272.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
