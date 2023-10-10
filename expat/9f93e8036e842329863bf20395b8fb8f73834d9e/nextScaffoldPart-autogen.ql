/**
 * @name expat-9f93e8036e842329863bf20395b8fb8f73834d9e-nextScaffoldPart
 * @id cpp/expat/9f93e8036e842329863bf20395b8fb8f73834d9e/nextScaffoldPart
 * @description expat-9f93e8036e842329863bf20395b8fb8f73834d9e-expat/lib/xmlparse.c-nextScaffoldPart CVE-2022-22822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdtd_7132, PointerFieldAccess target_1, IfStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scaffSize"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdtd_7132, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="scaffold"
		and target_1.getQualifier().(VariableAccess).getTarget()=vdtd_7132
}

predicate func_2(Variable vdtd_7132, IfStmt target_2) {
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="realloc_fcn"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="32"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="malloc_fcn"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(MulExpr).getValue()="1024"
		and target_2.getElse().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getElse().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Variable vdtd_7132, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="realloc_fcn"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_mem"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="scaffSize"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="32"
}

from Function func, Variable vdtd_7132, PointerFieldAccess target_1, IfStmt target_2, ExprStmt target_3
where
not func_0(vdtd_7132, target_1, target_2, target_3)
and func_1(vdtd_7132, target_1)
and func_2(vdtd_7132, target_2)
and func_3(vdtd_7132, target_3)
and vdtd_7132.getType().hasName("DTD *const")
and vdtd_7132.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
