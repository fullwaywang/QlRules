/**
 * @name linux-a0ad220c96692eda76b2e3fd7279f3dcd1d8a8ff-ims_pcu_parse_cdc_data
 * @id cpp/linux/a0ad220c96692eda76b2e3fd7279f3dcd1d8a8ff/ims_pcu_parse_cdc_data
 * @description linux-a0ad220c96692eda76b2e3fd7279f3dcd1d8a8ff-ims_pcu_parse_cdc_data 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vpcu_1655, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ctrl_intf"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcu_1655
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vpcu_1655, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="data_intf"
		and target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcu_1655
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vpcu_1655) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="udev"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpcu_1655)
}

from Function func, Parameter vpcu_1655
where
not func_0(vpcu_1655, func)
and not func_1(vpcu_1655, func)
and vpcu_1655.getType().hasName("ims_pcu *")
and func_2(vpcu_1655)
and vpcu_1655.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
