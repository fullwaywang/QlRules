/**
 * @name ghostscript-7861fcad13c497728189feafb41cd57b5b50ea25-sampled_data_continue
 * @id cpp/ghostscript/7861fcad13c497728189feafb41cd57b5b50ea25/sampled-data-continue
 * @description ghostscript-7861fcad13c497728189feafb41cd57b5b50ea25-psi/zfsample.c-sampled_data_continue CVE-2021-45944
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vop_480, Variable vstack_depth_adjust_488, VariableAccess target_3, PointerArithmeticOperation target_4, RelationalOperation target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vop_480
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bot"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="p"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="requested"
		and target_0.getElse().(BlockStmt).getStmt(2) instanceof DoStmt
		and target_0.getElse().(BlockStmt).getStmt(3) instanceof ForStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vop_480, Variable vstack_depth_adjust_488, VariableAccess target_3, DoStmt target_1) {
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vop_480
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="requested"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="p"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vop_480
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Variable vop_480, Variable vi_484, Variable vstack_depth_adjust_488, VariableAccess target_3, ForStmt target_2) {
		target_2.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_484
		and target_2.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_484
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_2.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_484
		and target_2.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_2.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_2.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vop_480
		and target_2.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vi_484
		and target_2.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="3840"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vstack_depth_adjust_488, VariableAccess target_3) {
		target_3.getTarget()=vstack_depth_adjust_488
}

predicate func_4(Variable vop_480, Variable vi_484, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vop_480
		and target_4.getAnOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_484
		and target_4.getAnOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vop_480, Variable vstack_depth_adjust_488, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vop_480
		and target_5.getGreaterOperand().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="3"
		and target_5.getGreaterOperand().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_5.getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="stack"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="op_stack"
		and target_5.getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("i_ctx_t *")
}

predicate func_6(Variable vstack_depth_adjust_488, ExprStmt target_6) {
		target_6.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vstack_depth_adjust_488
		and target_6.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vop_480, Variable vi_484, Variable vstack_depth_adjust_488, DoStmt target_1, ForStmt target_2, VariableAccess target_3, PointerArithmeticOperation target_4, RelationalOperation target_5, ExprStmt target_6
where
not func_0(vop_480, vstack_depth_adjust_488, target_3, target_4, target_5, target_6)
and func_1(vop_480, vstack_depth_adjust_488, target_3, target_1)
and func_2(vop_480, vi_484, vstack_depth_adjust_488, target_3, target_2)
and func_3(vstack_depth_adjust_488, target_3)
and func_4(vop_480, vi_484, target_4)
and func_5(vop_480, vstack_depth_adjust_488, target_5)
and func_6(vstack_depth_adjust_488, target_6)
and vop_480.getType().hasName("os_ptr")
and vi_484.getType().hasName("int")
and vstack_depth_adjust_488.getType().hasName("int")
and vop_480.(LocalVariable).getFunction() = func
and vi_484.(LocalVariable).getFunction() = func
and vstack_depth_adjust_488.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
