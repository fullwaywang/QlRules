/**
 * @name openssh-b3855ff053f5078ec3d3c653cdaedefaa5fc362d-order_hostkeyalgs
 * @id cpp/openssh/b3855ff053f5078ec3d3c653cdaedefaa5fc362d/order-hostkeyalgs
 * @description openssh-b3855ff053f5078ec3d3c653cdaedefaa5fc362d-sshconnect2.c-order_hostkeyalgs CVE-2020-14145
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

predicate func_1(Function func) {
	exists(Initializer target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getExpr().getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Initializer target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getExpr().getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Initializer target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getExpr().getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Initializer target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getExpr().getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Initializer target_5 |
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getExpr().getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Initializer target_6 |
		target_6.getExpr().(Literal).getValue()="0"
		and target_6.getExpr().getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Initializer target_8 |
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getExpr().getEnclosingFunction() = func)
}

predicate func_9(Variable voptions, ArrayExpr target_13, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("first_alg")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hostkeyalgorithms"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_9)
		and target_13.getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_10(Variable vret_108, Variable vhostkeys_110, Variable voptions, AddressOfExpr target_14, ExprStmt target_15, LogicalAndExpr target_16, ValueFieldAccess target_17, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(FunctionCall).getTarget().hasName("lookup_key_in_hostkeys_by_type")
		and target_10.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhostkeys_110
		and target_10.getCondition().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("sshkey_type_plain")
		and target_10.getCondition().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("sshkey_type_from_name")
		and target_10.getCondition().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_10.getCondition().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("debug3")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: have matching best-preference key type %s, using HostkeyAlgorithms verbatim"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char[18]")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("char *")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_108
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="hostkeyalgorithms"
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions
		and target_10.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_10.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="out"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_10)
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation())
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_12))
}

predicate func_13(Variable voptions, ArrayExpr target_13) {
		target_13.getArrayBase().(ValueFieldAccess).getTarget().getName()="system_hostfiles"
		and target_13.getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions
}

predicate func_14(Variable vret_108, AddressOfExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vret_108
}

predicate func_15(Variable vhostkeys_110, Variable voptions, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("load_hostkeys")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhostkeys_110
		and target_15.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="system_hostfiles"
		and target_15.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions
}

predicate func_16(Variable vhostkeys_110, LogicalAndExpr target_16) {
		target_16.getAnOperand().(FunctionCall).getTarget().hasName("sshkey_type_is_cert")
		and target_16.getAnOperand().(FunctionCall).getTarget().hasName("lookup_marker_in_hostkeys")
		and target_16.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhostkeys_110
}

predicate func_17(Variable voptions, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="hostkeyalgorithms"
		and target_17.getQualifier().(VariableAccess).getTarget()=voptions
}

from Function func, Variable vret_108, Variable vhostkeys_110, Variable voptions, ArrayExpr target_13, AddressOfExpr target_14, ExprStmt target_15, LogicalAndExpr target_16, ValueFieldAccess target_17
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and not func_5(func)
and not func_6(func)
and not func_8(func)
and not func_9(voptions, target_13, func)
and not func_10(vret_108, vhostkeys_110, voptions, target_14, target_15, target_16, target_17, func)
and not func_12(func)
and func_13(voptions, target_13)
and func_14(vret_108, target_14)
and func_15(vhostkeys_110, voptions, target_15)
and func_16(vhostkeys_110, target_16)
and func_17(voptions, target_17)
and vret_108.getType().hasName("char *")
and vhostkeys_110.getType().hasName("hostkeys *")
and voptions.getType().hasName("Options")
and vret_108.getParentScope+() = func
and vhostkeys_110.getParentScope+() = func
and not voptions.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
