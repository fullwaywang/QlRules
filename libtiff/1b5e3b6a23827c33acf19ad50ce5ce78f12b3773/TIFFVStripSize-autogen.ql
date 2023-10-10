/**
 * @name libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-TIFFVStripSize
 * @id cpp/libtiff/1b5e3b6a23827c33acf19ad50ce5ce78f12b3773/TIFFVStripSize
 * @description libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-libtiff/tif_strip.c-TIFFVStripSize CVE-2019-14973
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmodule_130, Variable vm_131, Parameter vtif_128, ExprStmt target_10, EqualityOperation target_11) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_TIFFCastUInt64ToSSize")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtif_128
		and target_0.getArgument(1).(VariableAccess).getTarget()=vm_131
		and target_0.getArgument(2).(VariableAccess).getTarget()=vmodule_130
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vm_131, Variable vn_132, VariableAccess target_1) {
		target_1.getTarget()=vm_131
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_132
}

predicate func_2(Parameter vtif_128, VariableAccess target_2) {
		target_2.getTarget()=vtif_128
		and target_2.getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Variable vmodule_130, VariableAccess target_3) {
		target_3.getTarget()=vmodule_130
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Function func, DeclStmt target_4) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vm_131, Variable vn_132, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_132
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vm_131
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vmodule_130, Variable vm_131, Variable vn_132, Parameter vtif_128, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vn_132
		and target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vm_131
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_128
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_130
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_132
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

/*predicate func_7(Variable vmodule_130, Parameter vtif_128, EqualityOperation target_11, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_7.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_128
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmodule_130
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

*/
predicate func_8(Variable vn_132, EqualityOperation target_11, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_132
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_9(Variable vn_132, ExprStmt target_8, VariableAccess target_9) {
		target_9.getTarget()=vn_132
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getLocation())
}

predicate func_10(Variable vm_131, Parameter vtif_128, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vm_131
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFVStripSize64")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_128
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_11(Variable vm_131, Variable vn_132, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vn_132
		and target_11.getAnOperand().(VariableAccess).getTarget()=vm_131
}

from Function func, Variable vmodule_130, Variable vm_131, Variable vn_132, Parameter vtif_128, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, DeclStmt target_4, ExprStmt target_5, IfStmt target_6, ExprStmt target_8, VariableAccess target_9, ExprStmt target_10, EqualityOperation target_11
where
not func_0(vmodule_130, vm_131, vtif_128, target_10, target_11)
and func_1(vm_131, vn_132, target_1)
and func_2(vtif_128, target_2)
and func_3(vmodule_130, target_3)
and func_4(func, target_4)
and func_5(vm_131, vn_132, func, target_5)
and func_6(vmodule_130, vm_131, vn_132, vtif_128, func, target_6)
and func_8(vn_132, target_11, target_8)
and func_9(vn_132, target_8, target_9)
and func_10(vm_131, vtif_128, target_10)
and func_11(vm_131, vn_132, target_11)
and vmodule_130.getType().hasName("const char[]")
and vm_131.getType().hasName("uint64")
and vn_132.getType().hasName("tmsize_t")
and vtif_128.getType().hasName("TIFF *")
and vmodule_130.(LocalVariable).getFunction() = func
and vm_131.(LocalVariable).getFunction() = func
and vn_132.(LocalVariable).getFunction() = func
and vtif_128.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
