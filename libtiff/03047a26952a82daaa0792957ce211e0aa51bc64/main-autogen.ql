/**
 * @name libtiff-03047a26952a82daaa0792957ce211e0aa51bc64-main
 * @id cpp/libtiff/03047a26952a82daaa0792957ce211e0aa51bc64/main
 * @description libtiff-03047a26952a82daaa0792957ce211e0aa51bc64-tools/tiffset.c-main CVE-2022-22844
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtiff_92, Variable varg_index_93, Variable vstderr, Variable vfip_137, Parameter vargv_90, EqualityOperation target_2, ExprStmt target_3, EqualityOperation target_4, ArrayExpr target_5, ExprStmt target_6, ExprStmt target_7, FunctionCall target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("TIFFFieldPassCount")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="65535"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_92
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFieldTag")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("size_t")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to set %s=%s\n"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("TIFFFieldName")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargv_90
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=varg_index_93
		and target_0.getElse() instanceof BlockStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtiff_92, Variable varg_index_93, Variable vstderr, Variable vfip_137, Parameter vargv_90, EqualityOperation target_2, BlockStmt target_1) {
		target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_92
		and target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFieldTag")
		and target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
		and target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargv_90
		and target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=varg_index_93
		and target_1.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to set %s=%s\n"
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("TIFFFieldName")
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargv_90
		and target_1.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=varg_index_93
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vfip_137, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("TIFFFieldDataType")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
}

predicate func_3(Variable vtiff_92, Variable vfip_137, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfip_137
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetField")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_92
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
}

predicate func_4(Variable vtiff_92, Variable varg_index_93, Variable vfip_137, Parameter vargv_90, EqualityOperation target_4) {
		target_4.getAnOperand().(FunctionCall).getTarget().hasName("TIFFSetField")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_92
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFieldTag")
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargv_90
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=varg_index_93
		and target_4.getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable varg_index_93, Parameter vargv_90, ArrayExpr target_5) {
		target_5.getArrayBase().(VariableAccess).getTarget()=vargv_90
		and target_5.getArrayOffset().(VariableAccess).getTarget()=varg_index_93
}

predicate func_6(Variable vstderr, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_6.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to unset %s\n"
		and target_6.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("TIFFFieldName")
		and target_6.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const TIFFField *")
}

predicate func_7(Variable varg_index_93, Variable vstderr, Variable vfip_137, Parameter vargv_90, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstderr
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to set %s=%s\n"
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("TIFFFieldName")
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfip_137
		and target_7.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargv_90
		and target_7.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=varg_index_93
}

predicate func_8(Variable vfip_137, FunctionCall target_8) {
		target_8.getTarget().hasName("TIFFFieldTag")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vfip_137
}

from Function func, Variable vtiff_92, Variable varg_index_93, Variable vstderr, Variable vfip_137, Parameter vargv_90, BlockStmt target_1, EqualityOperation target_2, ExprStmt target_3, EqualityOperation target_4, ArrayExpr target_5, ExprStmt target_6, ExprStmt target_7, FunctionCall target_8
where
not func_0(vtiff_92, varg_index_93, vstderr, vfip_137, vargv_90, target_2, target_3, target_4, target_5, target_6, target_7, target_8)
and func_1(vtiff_92, varg_index_93, vstderr, vfip_137, vargv_90, target_2, target_1)
and func_2(vfip_137, target_2)
and func_3(vtiff_92, vfip_137, target_3)
and func_4(vtiff_92, varg_index_93, vfip_137, vargv_90, target_4)
and func_5(varg_index_93, vargv_90, target_5)
and func_6(vstderr, target_6)
and func_7(varg_index_93, vstderr, vfip_137, vargv_90, target_7)
and func_8(vfip_137, target_8)
and vtiff_92.getType().hasName("TIFF *")
and varg_index_93.getType().hasName("int")
and vstderr.getType().hasName("FILE *")
and vfip_137.getType().hasName("const TIFFField *")
and vargv_90.getType().hasName("char *[]")
and vtiff_92.(LocalVariable).getFunction() = func
and varg_index_93.(LocalVariable).getFunction() = func
and not vstderr.getParentScope+() = func
and vfip_137.(LocalVariable).getFunction() = func
and vargv_90.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
