/**
 * @name linux-b4487b93545214a9db8cbf32e86411677b0cca21-decode_attr_security_label
 * @id cpp/linux/b4487b93545214a9db8cbf32e86411677b0cca21/decode_attr_security_label
 * @description linux-b4487b93545214a9db8cbf32e86411677b0cca21-decode_attr_security_label 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vlabel_4141, Variable vlen_4145) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_4145
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="34"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vlabel_4141)
}

predicate func_2(Parameter vlabel_4141, Variable vlen_4145, Variable vp_4146) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("__memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="label"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_4146
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_4145
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vlabel_4141)
}

predicate func_3(Parameter vlabel_4141, Variable vpi_4143, Variable vlfs_4144, Variable vlen_4145, Variable vstatus_4147) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vlabel_4141
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_4145
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pi"
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_3.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpi_4143
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lfs"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlfs_4144
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_4147
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="25"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_4145
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2048")
}

predicate func_4(Parameter vlabel_4141, Variable vpi_4143, Variable vlfs_4144, Variable vlen_4145) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vlen_4145
		and target_4.getGreaterOperand().(Literal).getValue()="2048"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vlabel_4141
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_4145
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pi"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpi_4143
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lfs"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlabel_4141
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlfs_4144)
}

from Function func, Parameter vlabel_4141, Variable vpi_4143, Variable vlfs_4144, Variable vlen_4145, Variable vp_4146, Variable vstatus_4147
where
not func_0(vlabel_4141, vlen_4145)
and func_2(vlabel_4141, vlen_4145, vp_4146)
and vlabel_4141.getType().hasName("nfs4_label *")
and func_3(vlabel_4141, vpi_4143, vlfs_4144, vlen_4145, vstatus_4147)
and vpi_4143.getType().hasName("uint32_t")
and vlfs_4144.getType().hasName("uint32_t")
and vlen_4145.getType().hasName("__u32")
and func_4(vlabel_4141, vpi_4143, vlfs_4144, vlen_4145)
and vp_4146.getType().hasName("__be32 *")
and vstatus_4147.getType().hasName("int")
and vlabel_4141.getParentScope+() = func
and vpi_4143.getParentScope+() = func
and vlfs_4144.getParentScope+() = func
and vlen_4145.getParentScope+() = func
and vp_4146.getParentScope+() = func
and vstatus_4147.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
