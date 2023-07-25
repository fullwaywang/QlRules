/**
 * @name freerdp-b8beb55913471952f92770c90c372139d78c16c0-update_write_brush
 * @id cpp/freerdp/b8beb55913471952f92770c90c372139d78c16c0/update-write-brush
 * @description freerdp-b8beb55913471952f92770c90c372139d78c16c0-libfreerdp/core/orders.c-update_write_brush CVE-2020-11096
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbrush_842, ExprStmt target_4, EqualityOperation target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_bmf_bpp")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="style"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbrush_842
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(BitwiseAndExpr target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("BOOL")
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vbrush_842, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="style"
		and target_2.getQualifier().(VariableAccess).getTarget()=vbrush_842
}

predicate func_3(Parameter vbrush_842, Variable vBMF_BPP, ArrayExpr target_3) {
		target_3.getArrayBase().(VariableAccess).getTarget()=vBMF_BPP
		and target_3.getArrayOffset().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="style"
		and target_3.getArrayOffset().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbrush_842
		and target_3.getArrayOffset().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="7"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbrush_842
}

predicate func_4(Parameter vbrush_842, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbrush_842
		and target_4.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
}

predicate func_5(Parameter vbrush_842, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbrush_842
		and target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Parameter vbrush_842, BitwiseAndExpr target_6) {
		target_6.getLeftOperand().(PointerFieldAccess).getTarget().getName()="style"
		and target_6.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbrush_842
		and target_6.getRightOperand().(Literal).getValue()="128"
}

from Function func, Parameter vbrush_842, Variable vBMF_BPP, PointerFieldAccess target_2, ArrayExpr target_3, ExprStmt target_4, EqualityOperation target_5, BitwiseAndExpr target_6
where
not func_0(vbrush_842, target_4, target_5)
and not func_1(target_6, func)
and func_2(vbrush_842, target_2)
and func_3(vbrush_842, vBMF_BPP, target_3)
and func_4(vbrush_842, target_4)
and func_5(vbrush_842, target_5)
and func_6(vbrush_842, target_6)
and vbrush_842.getType().hasName("rdpBrush *")
and vBMF_BPP.getType() instanceof ArrayType
and vbrush_842.getParentScope+() = func
and not vBMF_BPP.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
