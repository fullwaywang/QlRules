/**
 * @name vim-8ecfa2c56b4992c7f067b92488aa9acea5a454ad-movemark
 * @id cpp/vim/8ecfa2c56b4992c7f067b92488aa9acea5a454ad/movemark
 * @description vim-8ecfa2c56b4992c7f067b92488aa9acea5a454ad-src/mark.c-movemark CVE-2022-3256
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Variable vcurwin, Parameter vcount_188, IfStmt target_4) {
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_188
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_188
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistlen"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Variable vcurwin, Parameter vcount_188, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistlen"
		and target_5.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setpcmark")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixDecrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_188
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_6(Variable vcurwin, Parameter vcount_188, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_6.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcount_188
}

predicate func_7(Variable vjmp_191, Variable vcurwin, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vjmp_191
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplist"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="w_jumplistidx"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
}

predicate func_8(Variable vjmp_191, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="fnum"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fname2fnum")
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjmp_191
}

predicate func_9(Variable vpos_190, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vpos_190
}

predicate func_10(Variable vjmp_191, VariableAccess target_10) {
		target_10.getTarget()=vjmp_191
}

predicate func_11(Variable vjmp_191, EqualityOperation target_15, ValueFieldAccess target_16, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="fmark"
		and target_11.getQualifier().(VariableAccess).getTarget()=vjmp_191
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(VariableAccess).getLocation())
		and target_11.getQualifier().(VariableAccess).getLocation().isBefore(target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Variable vjmp_191, ValueFieldAccess target_17, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="fmark"
		and target_12.getQualifier().(VariableAccess).getTarget()=vjmp_191
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(VariableAccess).getLocation())
}

predicate func_13(Variable vjmp_191, ExprStmt target_18, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="fmark"
		and target_13.getQualifier().(VariableAccess).getTarget()=vjmp_191
		and target_13.getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_14(Variable vjmp_191, ValueFieldAccess target_19, ExprStmt target_20, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="fmark"
		and target_14.getQualifier().(VariableAccess).getTarget()=vjmp_191
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getQualifier().(VariableAccess).getLocation())
		and target_14.getQualifier().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_15(Variable vjmp_191, EqualityOperation target_15) {
		target_15.getAnOperand().(ValueFieldAccess).getTarget().getName()="fnum"
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
		and target_15.getAnOperand().(PointerFieldAccess).getTarget().getName()="b_fnum"
}

predicate func_16(Variable vjmp_191, ValueFieldAccess target_16) {
		target_16.getTarget().getName()="fnum"
		and target_16.getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
}

predicate func_17(Variable vjmp_191, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="fnum"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
}

predicate func_18(Variable vjmp_191, Variable vcurwin, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="w_cursor"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcurwin
		and target_18.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="mark"
		and target_18.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_18.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
}

predicate func_19(Variable vjmp_191, ValueFieldAccess target_19) {
		target_19.getTarget().getName()="mark"
		and target_19.getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
}

predicate func_20(Variable vpos_190, Variable vjmp_191, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpos_190
		and target_20.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mark"
		and target_20.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="fmark"
		and target_20.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vjmp_191
}

from Function func, Variable vpos_190, Variable vjmp_191, Variable vcurwin, Parameter vcount_188, IfStmt target_4, IfStmt target_5, ExprStmt target_6, ExprStmt target_7, IfStmt target_8, ReturnStmt target_9, VariableAccess target_10, PointerFieldAccess target_11, PointerFieldAccess target_12, PointerFieldAccess target_13, PointerFieldAccess target_14, EqualityOperation target_15, ValueFieldAccess target_16, ValueFieldAccess target_17, ExprStmt target_18, ValueFieldAccess target_19, ExprStmt target_20
where
func_4(vcurwin, vcount_188, target_4)
and func_5(vcurwin, vcount_188, target_5)
and func_6(vcurwin, vcount_188, target_6)
and func_7(vjmp_191, vcurwin, target_7)
and func_8(vjmp_191, target_8)
and func_9(vpos_190, target_9)
and func_10(vjmp_191, target_10)
and func_11(vjmp_191, target_15, target_16, target_11)
and func_12(vjmp_191, target_17, target_12)
and func_13(vjmp_191, target_18, target_13)
and func_14(vjmp_191, target_19, target_20, target_14)
and func_15(vjmp_191, target_15)
and func_16(vjmp_191, target_16)
and func_17(vjmp_191, target_17)
and func_18(vjmp_191, vcurwin, target_18)
and func_19(vjmp_191, target_19)
and func_20(vpos_190, vjmp_191, target_20)
and vpos_190.getType().hasName("pos_T *")
and vjmp_191.getType().hasName("xfmark_T *")
and vcurwin.getType().hasName("win_T *")
and vcount_188.getType().hasName("int")
and vpos_190.getParentScope+() = func
and vjmp_191.getParentScope+() = func
and not vcurwin.getParentScope+() = func
and vcount_188.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
