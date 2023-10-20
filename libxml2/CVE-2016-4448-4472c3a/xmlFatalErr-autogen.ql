/**
 * @name libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlFatalErr
 * @id cpp/libxml2/4472c3a5a5b516aaf59b89be602fbce52756c3e9/xmlFatalErr
 * @description libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-parser.c-xmlFatalErr CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="128"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="128"
		and not target_1.getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vctxt_346, Parameter verror_346, Parameter vinfo_346, Variable verrmsg_348, LogicalAndExpr target_13, EqualityOperation target_14, SwitchStmt target_15, ExprStmt target_16, ExprStmt target_11) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("__xmlRaiseError")
		and target_2.getArgument(0) instanceof Literal
		and target_2.getArgument(1).(Literal).getValue()="0"
		and target_2.getArgument(2).(Literal).getValue()="0"
		and target_2.getArgument(3).(VariableAccess).getTarget()=vctxt_346
		and target_2.getArgument(4).(Literal).getValue()="0"
		and target_2.getArgument(6).(VariableAccess).getTarget()=verror_346
		and target_2.getArgument(8).(Literal).getValue()="0"
		and target_2.getArgument(9).(Literal).getValue()="0"
		and target_2.getArgument(10).(VariableAccess).getTarget()=vinfo_346
		and target_2.getArgument(11).(Literal).getValue()="0"
		and target_2.getArgument(12).(Literal).getValue()="0"
		and target_2.getArgument(13).(Literal).getValue()="0"
		and target_2.getArgument(14).(Literal).getValue()="0"
		and target_2.getArgument(15).(StringLiteral).getValue()="%s: %s\n"
		and target_2.getArgument(16).(VariableAccess).getTarget()=verrmsg_348
		and target_2.getArgument(17).(VariableAccess).getTarget()=vinfo_346
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(3).(VariableAccess).getLocation())
		and target_2.getArgument(3).(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(VariableAccess).getLocation().isBefore(target_2.getArgument(6).(VariableAccess).getLocation())
		and target_2.getArgument(6).(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(10).(VariableAccess).getLocation().isBefore(target_2.getArgument(10).(VariableAccess).getLocation()))
}

predicate func_4(Variable verrmsg_348, VariableAccess target_4) {
		target_4.getTarget()=verrmsg_348
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Parameter vctxt_346, Parameter verror_346, Parameter vinfo_346, VariableAccess target_5) {
		target_5.getTarget()=vinfo_346
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__xmlRaiseError")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctxt_346
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=verror_346
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vinfo_346
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(13).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(14).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(15) instanceof AddressOfExpr
}

predicate func_6(Variable verrmsg_348, VariableAccess target_6) {
		target_6.getTarget()=verrmsg_348
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Function func, DeclStmt target_8) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Variable verrmsg_348, Variable verrstr_349, FunctionCall target_9) {
		target_9.getTarget().hasName("snprintf")
		and target_9.getArgument(0).(VariableAccess).getTarget()=verrstr_349
		and target_9.getArgument(1) instanceof Literal
		and target_9.getArgument(2) instanceof StringLiteral
		and target_9.getArgument(3).(VariableAccess).getTarget()=verrmsg_348
}

predicate func_10(Variable verrmsg_348, Variable verrstr_349, FunctionCall target_10) {
		target_10.getTarget().hasName("snprintf")
		and target_10.getArgument(0).(VariableAccess).getTarget()=verrstr_349
		and target_10.getArgument(1) instanceof Literal
		and target_10.getArgument(2).(StringLiteral).getValue()="%s: %%s\n"
		and target_10.getArgument(3).(VariableAccess).getTarget()=verrmsg_348
}

predicate func_11(Parameter vctxt_346, Parameter verror_346, Parameter vinfo_346, Variable verrstr_349, Function func, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("__xmlRaiseError")
		and target_11.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctxt_346
		and target_11.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=verror_346
		and target_11.getExpr().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vinfo_346
		and target_11.getExpr().(FunctionCall).getArgument(11).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(13).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(14).(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(15).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=verrstr_349
		and target_11.getExpr().(FunctionCall).getArgument(15).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_11.getExpr().(FunctionCall).getArgument(16).(VariableAccess).getTarget()=vinfo_346
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

/*predicate func_12(Parameter vctxt_346, Parameter verror_346, Parameter vinfo_346, Variable verrstr_349, AddressOfExpr target_12) {
		target_12.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=verrstr_349
		and target_12.getOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__xmlRaiseError")
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vctxt_346
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=verror_346
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vinfo_346
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(11).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(13).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(14).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(16).(VariableAccess).getTarget()=vinfo_346
}

*/
predicate func_13(Parameter vctxt_346, LogicalAndExpr target_13) {
		target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vctxt_346
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="disableSAX"
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_346
		and target_13.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_346
}

predicate func_14(Parameter vctxt_346, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vctxt_346
		and target_14.getAnOperand().(Literal).getValue()="0"
}

predicate func_15(Parameter verror_346, Variable verrmsg_348, SwitchStmt target_15) {
		target_15.getExpr().(VariableAccess).getTarget()=verror_346
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_348
		and target_15.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="CharRef: invalid hexadecimal value"
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_348
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="CharRef: invalid decimal value"
		and target_15.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_348
		and target_15.getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="CharRef: invalid value"
}

predicate func_16(Parameter vctxt_346, Parameter verror_346, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="errNo"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_346
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=verror_346
}

from Function func, Parameter vctxt_346, Parameter verror_346, Parameter vinfo_346, Variable verrmsg_348, Variable verrstr_349, Literal target_0, Literal target_1, VariableAccess target_4, VariableAccess target_5, VariableAccess target_6, DeclStmt target_8, FunctionCall target_9, FunctionCall target_10, ExprStmt target_11, LogicalAndExpr target_13, EqualityOperation target_14, SwitchStmt target_15, ExprStmt target_16
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vctxt_346, verror_346, vinfo_346, verrmsg_348, target_13, target_14, target_15, target_16, target_11)
and func_4(verrmsg_348, target_4)
and func_5(vctxt_346, verror_346, vinfo_346, target_5)
and func_6(verrmsg_348, target_6)
and func_8(func, target_8)
and func_9(verrmsg_348, verrstr_349, target_9)
and func_10(verrmsg_348, verrstr_349, target_10)
and func_11(vctxt_346, verror_346, vinfo_346, verrstr_349, func, target_11)
and func_13(vctxt_346, target_13)
and func_14(vctxt_346, target_14)
and func_15(verror_346, verrmsg_348, target_15)
and func_16(vctxt_346, verror_346, target_16)
and vctxt_346.getType().hasName("xmlParserCtxtPtr")
and verror_346.getType().hasName("xmlParserErrors")
and vinfo_346.getType().hasName("const char *")
and verrmsg_348.getType().hasName("const char *")
and verrstr_349.getType().hasName("char[129]")
and vctxt_346.getFunction() = func
and verror_346.getFunction() = func
and vinfo_346.getFunction() = func
and verrmsg_348.(LocalVariable).getFunction() = func
and verrstr_349.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
