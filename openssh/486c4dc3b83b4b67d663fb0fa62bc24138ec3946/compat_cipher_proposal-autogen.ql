/**
 * @name openssh-486c4dc3b83b4b67d663fb0fa62bc24138ec3946-compat_cipher_proposal
 * @id cpp/openssh/486c4dc3b83b4b67d663fb0fa62bc24138ec3946/compat-cipher-proposal
 * @description openssh-486c4dc3b83b4b67d663fb0fa62bc24138ec3946-compat_cipher_proposal CVE-2023-25136
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcipher_prop_160) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xstrdup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vcipher_prop_160)
}

predicate func_1(Parameter vcipher_prop_160, Parameter vssh_160) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=vcipher_prop_160
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="compat"
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vssh_160
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4096")
}

predicate func_2(Parameter vcipher_prop_160) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vcipher_prop_160)
}

from Function func, Parameter vcipher_prop_160, Parameter vssh_160
where
not func_0(vcipher_prop_160)
and func_1(vcipher_prop_160, vssh_160)
and func_2(vcipher_prop_160)
and vcipher_prop_160.getType().hasName("char *")
and vssh_160.getType().hasName("ssh *")
and vcipher_prop_160.getParentScope+() = func
and vssh_160.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
