/**
 * @name yara-83d799804648c2a0895d40a19835d9b757c6fa4e-_yr_scan_verify_re_match
 * @id cpp/yara/83d799804648c2a0895d40a19835d9b757c6fa4e/-yr-scan-verify-re-match
 * @description yara-83d799804648c2a0895d40a19835d9b757c6fa4e-libyara/scan.c-_yr_scan_verify_re_match CVE-2017-8294
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_size_541, Parameter voffset_543, Variable vflags_550, ExprStmt target_9, SubExpr target_10, PointerArithmeticOperation target_11) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vdata_size_541
		and target_0.getRightOperand().(VariableAccess).getTarget()=voffset_543
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="backward_code"
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_543
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(VariableAccess).getTarget()=voffset_543
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_550
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getLeftOperand().(VariableAccess).getLocation())
		and target_10.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(VariableAccess).getLocation())
		and target_0.getRightOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter voffset_543, Variable vflags_550, VariableAccess target_2) {
		target_2.getTarget()=voffset_543
		and target_2.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="backward_code"
		and target_2.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_543
		and target_2.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_550
		and target_2.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="4"
		and target_2.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_3(Parameter voffset_543, VariableAccess target_3) {
		target_3.getTarget()=voffset_543
		and target_3.getParent().(GTExpr).getLesserOperand() instanceof Literal
}

predicate func_4(Variable vflags_550, VariableAccess target_4) {
		target_4.getTarget()=vflags_550
}

predicate func_5(Variable vflags_550, VariableAccess target_5) {
		target_5.getTarget()=vflags_550
}

predicate func_6(Parameter voffset_543, VariableAccess target_6) {
		target_6.getTarget()=voffset_543
		and target_6.getParent().(GTExpr).getLesserOperand() instanceof Literal
}

predicate func_7(Parameter vdata_size_541, Parameter voffset_543, Variable vflags_550, SubExpr target_10, SubExpr target_12, PointerArithmeticOperation target_13, ExprStmt target_14, ExprStmt target_15, ConditionalExpr target_7) {
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_543
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_7.getThen().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_550
		and target_7.getThen().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="256"
		and target_7.getElse().(VariableAccess).getTarget()=vflags_550
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="forward_code"
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_543
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vdata_size_541
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=voffset_543
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(4).(Literal).getValue()="0"
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(5).(Literal).getValue()="0"
		and target_7.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(VariableAccess).getLocation())
		and target_12.getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getThen().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_7.getThen().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_8(Parameter vdata_size_541, Parameter voffset_543, Variable vflags_550, SubExpr target_12, ExprStmt target_9, SubExpr target_10, PointerArithmeticOperation target_11, ExprStmt target_15, BitwiseOrExpr target_16, ConditionalExpr target_8) {
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_543
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_8.getThen().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_550
		and target_8.getThen().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="256"
		and target_8.getElse().(VariableAccess).getTarget()=vflags_550
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="forward_code"
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_543
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vdata_size_541
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=voffset_543
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(4).(Literal).getValue()="0"
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(5).(Literal).getValue()="0"
		and target_12.getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_8.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_10.getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getThen().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_8.getThen().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_16.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getLocation())
}

predicate func_9(Parameter vdata_size_541, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="data_size"
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata_size_541
}

predicate func_10(Parameter vdata_size_541, Parameter voffset_543, SubExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vdata_size_541
		and target_10.getRightOperand().(VariableAccess).getTarget()=voffset_543
}

predicate func_11(Parameter voffset_543, PointerArithmeticOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=voffset_543
}

predicate func_12(Parameter vdata_size_541, Parameter voffset_543, SubExpr target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vdata_size_541
		and target_12.getRightOperand().(VariableAccess).getTarget()=voffset_543
}

predicate func_13(Parameter voffset_543, PointerArithmeticOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=voffset_543
}

predicate func_14(Variable vflags_550, ExprStmt target_14) {
		target_14.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags_550
		and target_14.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
}

predicate func_15(Variable vflags_550, ExprStmt target_15) {
		target_15.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags_550
		and target_15.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="16"
}

predicate func_16(Variable vflags_550, BitwiseOrExpr target_16) {
		target_16.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_550
		and target_16.getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="4"
		and target_16.getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vdata_size_541, Parameter voffset_543, Variable vflags_550, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, ConditionalExpr target_7, ConditionalExpr target_8, ExprStmt target_9, SubExpr target_10, PointerArithmeticOperation target_11, SubExpr target_12, PointerArithmeticOperation target_13, ExprStmt target_14, ExprStmt target_15, BitwiseOrExpr target_16
where
not func_0(vdata_size_541, voffset_543, vflags_550, target_9, target_10, target_11)
and func_2(voffset_543, vflags_550, target_2)
and func_3(voffset_543, target_3)
and func_4(vflags_550, target_4)
and func_5(vflags_550, target_5)
and func_6(voffset_543, target_6)
and func_7(vdata_size_541, voffset_543, vflags_550, target_10, target_12, target_13, target_14, target_15, target_7)
and func_8(vdata_size_541, voffset_543, vflags_550, target_12, target_9, target_10, target_11, target_15, target_16, target_8)
and func_9(vdata_size_541, target_9)
and func_10(vdata_size_541, voffset_543, target_10)
and func_11(voffset_543, target_11)
and func_12(vdata_size_541, voffset_543, target_12)
and func_13(voffset_543, target_13)
and func_14(vflags_550, target_14)
and func_15(vflags_550, target_15)
and func_16(vflags_550, target_16)
and vdata_size_541.getType().hasName("size_t")
and voffset_543.getType().hasName("size_t")
and vflags_550.getType().hasName("int")
and vdata_size_541.getParentScope+() = func
and voffset_543.getParentScope+() = func
and vflags_550.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
