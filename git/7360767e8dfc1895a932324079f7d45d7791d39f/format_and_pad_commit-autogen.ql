/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-format_and_pad_commit
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/format-and-pad-commit
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-pretty.c-format_and_pad_commit CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Variable vstart_1675, ExprStmt target_13) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("strlen")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vstart_1675
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Variable vp_1702, Parameter vsb_1668, ExprStmt target_14, LogicalAndExpr target_15, LogicalAndExpr target_16, ExprStmt target_17) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_1702
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1668
		and target_5.getAnOperand() instanceof RelationalOperation
		and target_5.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_1702
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="27"
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Variable vlocal_sb_1672, AddressOfExpr target_18) {
	exists(ValueFieldAccess target_6 |
		target_6.getTarget().getName()="len"
		and target_6.getQualifier().(VariableAccess).getTarget()=vlocal_sb_1672
		and target_6.getQualifier().(VariableAccess).getLocation().isBefore(target_18.getOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vlocal_sb_1672, ValueFieldAccess target_8) {
		target_8.getTarget().getName()="len"
		and target_8.getQualifier().(VariableAccess).getTarget()=vlocal_sb_1672
}

predicate func_9(Variable vch_1700, Variable vp_1702, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vch_1700
		and target_9.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_1702
		and target_9.getGreaterOperand().(Literal).getValue()="10"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_1702
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="27"
}

predicate func_11(Variable vstart_1675, ExprStmt target_19, UnaryMinusExpr target_11) {
		target_11.getValue()="-1"
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("utf8_strnwidth")
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1675
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_12(Variable vlocal_sb_1672, AddressOfExpr target_20, AddressOfExpr target_21, UnaryMinusExpr target_12) {
		target_12.getValue()="-1"
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("utf8_strnwidth")
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="buf"
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlocal_sb_1672
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_20.getOperand().(VariableAccess).getLocation().isBefore(target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getOperand().(VariableAccess).getLocation())
}

predicate func_13(Variable vstart_1675, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("utf8_strnwidth")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1675
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof UnaryMinusExpr
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_14(Variable vch_1700, Variable vp_1702, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_1702
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vch_1700
		and target_14.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_15(Variable vp_1702, LogicalAndExpr target_15) {
		target_15.getAnOperand() instanceof RelationalOperation
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_1702
		and target_15.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="27"
}

predicate func_16(Variable vch_1700, Parameter vsb_1668, LogicalAndExpr target_16) {
		target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vch_1700
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1668
}

predicate func_17(Variable vch_1700, Parameter vsb_1668, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("strbuf_setlen")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_1668
		and target_17.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vch_1700
		and target_17.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_17.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_17.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1668
}

predicate func_18(Variable vlocal_sb_1672, AddressOfExpr target_18) {
		target_18.getOperand().(VariableAccess).getTarget()=vlocal_sb_1672
}

predicate func_19(Variable vstart_1675, Parameter vsb_1668, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_1675
		and target_19.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_19.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1668
}

predicate func_20(Variable vlocal_sb_1672, AddressOfExpr target_20) {
		target_20.getOperand().(VariableAccess).getTarget()=vlocal_sb_1672
}

predicate func_21(Variable vlocal_sb_1672, AddressOfExpr target_21) {
		target_21.getOperand().(VariableAccess).getTarget()=vlocal_sb_1672
}

from Function func, Variable vlocal_sb_1672, Variable vstart_1675, Variable vch_1700, Variable vp_1702, Parameter vsb_1668, ValueFieldAccess target_8, RelationalOperation target_9, UnaryMinusExpr target_11, UnaryMinusExpr target_12, ExprStmt target_13, ExprStmt target_14, LogicalAndExpr target_15, LogicalAndExpr target_16, ExprStmt target_17, AddressOfExpr target_18, ExprStmt target_19, AddressOfExpr target_20, AddressOfExpr target_21
where
not func_4(vstart_1675, target_13)
and not func_5(vp_1702, vsb_1668, target_14, target_15, target_16, target_17)
and not func_6(vlocal_sb_1672, target_18)
and func_8(vlocal_sb_1672, target_8)
and func_9(vch_1700, vp_1702, target_9)
and func_11(vstart_1675, target_19, target_11)
and func_12(vlocal_sb_1672, target_20, target_21, target_12)
and func_13(vstart_1675, target_13)
and func_14(vch_1700, vp_1702, target_14)
and func_15(vp_1702, target_15)
and func_16(vch_1700, vsb_1668, target_16)
and func_17(vch_1700, vsb_1668, target_17)
and func_18(vlocal_sb_1672, target_18)
and func_19(vstart_1675, vsb_1668, target_19)
and func_20(vlocal_sb_1672, target_20)
and func_21(vlocal_sb_1672, target_21)
and vlocal_sb_1672.getType().hasName("strbuf")
and vstart_1675.getType().hasName("const char *")
and vch_1700.getType().hasName("const char *")
and vp_1702.getType().hasName("const char *")
and vsb_1668.getType().hasName("strbuf *")
and vlocal_sb_1672.getParentScope+() = func
and vstart_1675.getParentScope+() = func
and vch_1700.getParentScope+() = func
and vp_1702.getParentScope+() = func
and vsb_1668.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
