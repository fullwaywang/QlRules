/**
 * @name libarchive-7f17c791dcfd8c0416e2cd2485b19410e47ef126-read_Header
 * @id cpp/libarchive/7f17c791dcfd8c0416e2cd2485b19410e47ef126/read-Header
 * @description libarchive-7f17c791dcfd8c0416e2cd2485b19410e47ef126-libarchive/archive_read_support_format_7zip.c-read_Header CVE-2016-8689
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh_2345, VariableAccess target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="emptyStreamBools"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vh_2345, VariableAccess target_5, ArrayExpr target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="emptyFileBools"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vh_2345, VariableAccess target_5, RelationalOperation target_9, ExprStmt target_10) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="antiBools"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_9.getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vzip_2348, LogicalOrExpr target_11, ExprStmt target_12) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="entry_names"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2348
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vh_2345, RelationalOperation target_13, ExprStmt target_14) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="attrBools"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_13.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vtype_2416, VariableAccess target_5) {
		target_5.getTarget()=vtype_2416
}

predicate func_6(Parameter vh_2345, Variable vzip_2348, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="emptyStreamBools"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="numFiles"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2348
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

predicate func_7(Parameter vh_2345, ArrayExpr target_7) {
		target_7.getArrayBase().(PointerFieldAccess).getTarget().getName()="emptyStreamBools"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
}

predicate func_8(Parameter vh_2345, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="emptyFileBools"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

predicate func_9(Parameter vh_2345, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(FunctionCall).getTarget().hasName("read_Bools")
		and target_9.getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="emptyFileBools"
		and target_9.getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_9.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_10(Parameter vh_2345, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="antiBools"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

predicate func_11(Variable vzip_2348, LogicalOrExpr target_11) {
		target_11.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="numFiles"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2348
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_12(Variable vzip_2348, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="entry_names"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2348
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
}

predicate func_13(Parameter vh_2345, Variable vtype_2416, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getLesserOperand().(FunctionCall).getTarget().hasName("read_Times")
		and target_13.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vh_2345
		and target_13.getLesserOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtype_2416
		and target_13.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_14(Parameter vh_2345, Variable vzip_2348, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="attrBools"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2345
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("calloc")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="numFiles"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2348
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1"
}

from Function func, Parameter vh_2345, Variable vzip_2348, Variable vtype_2416, VariableAccess target_5, ExprStmt target_6, ArrayExpr target_7, ExprStmt target_8, RelationalOperation target_9, ExprStmt target_10, LogicalOrExpr target_11, ExprStmt target_12, RelationalOperation target_13, ExprStmt target_14
where
not func_0(vh_2345, target_5, target_6)
and not func_1(vh_2345, target_5, target_7, target_8)
and not func_2(vh_2345, target_5, target_9, target_10)
and not func_3(vzip_2348, target_11, target_12)
and not func_4(vh_2345, target_13, target_14)
and func_5(vtype_2416, target_5)
and func_6(vh_2345, vzip_2348, target_6)
and func_7(vh_2345, target_7)
and func_8(vh_2345, target_8)
and func_9(vh_2345, target_9)
and func_10(vh_2345, target_10)
and func_11(vzip_2348, target_11)
and func_12(vzip_2348, target_12)
and func_13(vh_2345, vtype_2416, target_13)
and func_14(vh_2345, vzip_2348, target_14)
and vh_2345.getType().hasName("_7z_header_info *")
and vzip_2348.getType().hasName("_7zip *")
and vtype_2416.getType().hasName("int")
and vh_2345.getParentScope+() = func
and vzip_2348.getParentScope+() = func
and vtype_2416.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
