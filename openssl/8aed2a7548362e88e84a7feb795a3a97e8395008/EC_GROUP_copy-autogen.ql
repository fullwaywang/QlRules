/**
 * @name openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_copy
 * @id cpp/openssl/8aed2a7548362e88e84a7feb795a3a97e8395008/EC-GROUP-copy
 * @description openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_copy NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdest_171, Parameter vsrc_171, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_171
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_171
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BN_MONT_CTX_new")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_MONT_CTX_copy")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_171
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_171
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_171
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_MONT_CTX_free")
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_8(Parameter vdest_171, Variable vd_173, Variable vt_192) {
	exists(AddressOfExpr target_8 |
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="extra_data"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_171
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("EC_EX_DATA_set_data")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vt_192
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="dup_func"
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_173
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="free_func"
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_173
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="clear_free_func"
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_173)
}

predicate func_9(Parameter vsrc_171, Variable vd_173) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vd_173
		and target_9.getRValue().(PointerFieldAccess).getTarget().getName()="extra_data"
		and target_9.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_171)
}

from Function func, Parameter vdest_171, Parameter vsrc_171, Variable vd_173, Variable vt_192
where
not func_0(vdest_171, vsrc_171, func)
and vdest_171.getType().hasName("EC_GROUP *")
and func_8(vdest_171, vd_173, vt_192)
and vsrc_171.getType().hasName("const EC_GROUP *")
and func_9(vsrc_171, vd_173)
and vd_173.getType().hasName("EC_EXTRA_DATA *")
and vt_192.getType().hasName("void *")
and vdest_171.getParentScope+() = func
and vsrc_171.getParentScope+() = func
and vd_173.getParentScope+() = func
and vt_192.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
