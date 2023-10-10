/**
 * @name linux-a1b14d27ed0965838350f1377ff97c93ee383492-adjust_branches
 * @id cpp/linux/a1b14d27ed0965838350f1377ff97c93ee383492/adjust_branches
 * @description linux-a1b14d27ed0965838350f1377ff97c93ee383492-adjust_branches 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vi_2074, Parameter vpos_2070, Parameter vdelta_2070, Variable vinsn_2072) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand() instanceof AddExpr
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpos_2070
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdelta_2070
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_2074
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vpos_2070
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdelta_2070
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_2072
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vdelta_2070)
}

predicate func_2(Variable vi_2074, Variable vinsn_2072) {
	exists(AddExpr target_2 |
		target_2.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_2074
		and target_2.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="off"
		and target_2.getAnOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_2072
		and target_2.getAnOperand().(Literal).getValue()="1")
}

predicate func_5(Variable vi_2074, Parameter vpos_2070, Parameter vdelta_2070, Variable vinsn_2072) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand() instanceof AddExpr
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vpos_2070
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_2074
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vpos_2070
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_2072
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vdelta_2070)
}

predicate func_6(Parameter vdelta_2070, Variable vinsn_2072) {
	exists(AssignAddExpr target_6 |
		target_6.getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinsn_2072
		and target_6.getRValue().(VariableAccess).getTarget()=vdelta_2070)
}

from Function func, Variable vi_2074, Parameter vpos_2070, Parameter vdelta_2070, Variable vinsn_2072
where
not func_1(vi_2074, vpos_2070, vdelta_2070, vinsn_2072)
and func_2(vi_2074, vinsn_2072)
and func_5(vi_2074, vpos_2070, vdelta_2070, vinsn_2072)
and vi_2074.getType().hasName("int")
and vpos_2070.getType().hasName("int")
and vdelta_2070.getType().hasName("int")
and func_6(vdelta_2070, vinsn_2072)
and vinsn_2072.getType().hasName("bpf_insn *")
and vi_2074.getParentScope+() = func
and vpos_2070.getParentScope+() = func
and vdelta_2070.getParentScope+() = func
and vinsn_2072.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
