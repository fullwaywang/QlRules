/**
 * @name linux-350a5c4dd2452ea999cc5e1d4a8dbf12de2f97ef-map_create
 * @id cpp/linux/350a5c4dd2452ea999cc5e1d4a8dbf12de2f97ef/map_create
 * @description linux-350a5c4dd2452ea999cc5e1d4a8dbf12de2f97ef-map_create 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable verr_804, Variable vbtf_850, Parameter vattr_799) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("btf_is_kernel")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbtf_850
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("btf_put")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbtf_850
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_804
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="13"
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="btf_key_type_id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_799
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="btf_value_type_id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_799
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="btf_vmlinux_value_type_id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_799)
}

predicate func_4(Variable vbtf_850) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("PTR_ERR")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vbtf_850)
}

from Function func, Variable verr_804, Variable vbtf_850, Parameter vattr_799
where
not func_0(verr_804, vbtf_850, vattr_799)
and verr_804.getType().hasName("int")
and vbtf_850.getType().hasName("btf *")
and func_4(vbtf_850)
and vattr_799.getType().hasName("bpf_attr *")
and verr_804.getParentScope+() = func
and vbtf_850.getParentScope+() = func
and vattr_799.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
