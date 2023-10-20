/**
 * @name clamav-8bb3716be9c7ab7c6a3a1889267b1072f48af87b-blobAddData
 * @id cpp/clamav/8bb3716be9c7ab7c6a3a1889267b1072f48af87b/blobAddData
 * @description clamav-8bb3716be9c7ab7c6a3a1889267b1072f48af87b-libclamav/blob.c-blobAddData CVE-2020-3481
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Parameter vb_176, EqualityOperation target_4, ExprStmt target_5, RelationalOperation target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vb_176, PointerFieldAccess target_7, ExprStmt target_8) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(PointerFieldAccess target_7, Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vb_176, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vb_176, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cli_malloc")
}

predicate func_6(Parameter vb_176, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_6.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
		and target_6.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_6.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
}

predicate func_7(Parameter vb_176, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="data"
		and target_7.getQualifier().(VariableAccess).getTarget()=vb_176
}

predicate func_8(Parameter vb_176, ExprStmt target_8) {
		target_8.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_8.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vb_176
}

from Function func, Parameter vb_176, EqualityOperation target_4, ExprStmt target_5, RelationalOperation target_6, PointerFieldAccess target_7, ExprStmt target_8
where
not func_0(func)
and not func_1(vb_176, target_4, target_5, target_6)
and not func_2(vb_176, target_7, target_8)
and not func_3(target_7, func)
and func_4(vb_176, target_4)
and func_5(vb_176, target_5)
and func_6(vb_176, target_6)
and func_7(vb_176, target_7)
and func_8(vb_176, target_8)
and vb_176.getType().hasName("blob *")
and vb_176.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
