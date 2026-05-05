#
#
#
if [ ! -d "env_unix" ]; then
   echo "1. Creando ambiente"
   python -m venv env_unix
else
   echo "1. Ya existe un ambiente"
fi

echo "2. Activando ambiente"
source env_unix/bin/activate

echo "3. Instalando paquetes"
pip install --upgrade pip
pip install -r requirements.txt

#pip install opencv-python capstone Pillow scipy
#pip freeze > requirements.txt
