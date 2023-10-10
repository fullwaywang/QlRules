/**
 * @name libtiff-3144e57770c1e4d26520d8abee750f8ac8b75490-TIFFWriteDirectoryTagCheckedRational
 * @id cpp/libtiff/3144e57770c1e4d26520d8abee750f8ac8b75490/TIFFWriteDirectoryTagCheckedRational
 * @description libtiff-3144e57770c1e4d26520d8abee750f8ac8b75490-libtiff/tif_dirwrite.c-TIFFWriteDirectoryTagCheckedRational CVE-2017-7597
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_2095, BlockStmt target_7, RelationalOperation target_8, EqualityOperation target_4) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_0.getAnOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_8.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vmodule_2097, Parameter vtif_2095, EqualityOperation target_4, ExprStmt target_9, BitwiseAndExpr target_10) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_2095
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_2097
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not-a-number value is illegal"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_4, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vm_2098, Parameter vvalue_2095, EqualityOperation target_4, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="4294967295"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_2095
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_3.getElse() instanceof IfStmt
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_3
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_4
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vvalue_2095, BlockStmt target_7, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_4.getAnOperand().(Literal).getValue()="0.0"
		and target_4.getParent().(IfStmt).getThen()=target_7
}

predicate func_5(Variable vm_2098, Parameter vvalue_2095, EqualityOperation target_4, IfStmt target_5) {
		target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1.0"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(HexLiteral).getValue()="4294967295"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="4294967295"
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="4294967295"
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(HexLiteral).getValue()="4294967295"
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_5.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_6(Parameter vvalue_2095, BlockStmt target_14, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_6.getAnOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_6.getParent().(IfStmt).getThen()=target_14
}

predicate func_7(Variable vm_2098, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_8(Parameter vvalue_2095, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_8.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vmodule_2097, Parameter vtif_2095, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_2095
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_2097
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Negative value is illegal"
}

predicate func_10(Parameter vtif_2095, BitwiseAndExpr target_10) {
		target_10.getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_10.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_2095
		and target_10.getRightOperand().(Literal).getValue()="128"
}

predicate func_11(Variable vm_2098, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_12(Variable vm_2098, Parameter vvalue_2095, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vvalue_2095
		and target_12.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(HexLiteral).getValue()="4294967295"
}

predicate func_13(Variable vm_2098, Parameter vvalue_2095, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_13.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_2095
}

predicate func_14(Variable vm_2098, Parameter vvalue_2095, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_2095
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vm_2098
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Variable vm_2098, Parameter vvalue_2095, Variable vmodule_2097, Parameter vtif_2095, EqualityOperation target_4, IfStmt target_5, EqualityOperation target_6, BlockStmt target_7, RelationalOperation target_8, ExprStmt target_9, BitwiseAndExpr target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, BlockStmt target_14
where
not func_0(vvalue_2095, target_7, target_8, target_4)
and not func_1(vmodule_2097, vtif_2095, target_4, target_9, target_10)
and not func_2(target_4, func)
and not func_3(vm_2098, vvalue_2095, target_4, target_11, target_12, target_13)
and func_4(vvalue_2095, target_7, target_4)
and func_5(vm_2098, vvalue_2095, target_4, target_5)
and func_6(vvalue_2095, target_14, target_6)
and func_7(vm_2098, target_7)
and func_8(vvalue_2095, target_8)
and func_9(vmodule_2097, vtif_2095, target_9)
and func_10(vtif_2095, target_10)
and func_11(vm_2098, target_11)
and func_12(vm_2098, vvalue_2095, target_12)
and func_13(vm_2098, vvalue_2095, target_13)
and func_14(vm_2098, vvalue_2095, target_14)
and vm_2098.getType().hasName("uint32[2]")
and vvalue_2095.getType().hasName("double")
and vmodule_2097.getType().hasName("const char[]")
and vtif_2095.getType().hasName("TIFF *")
and vm_2098.(LocalVariable).getFunction() = func
and vvalue_2095.getFunction() = func
and vmodule_2097.(LocalVariable).getFunction() = func
and vtif_2095.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
